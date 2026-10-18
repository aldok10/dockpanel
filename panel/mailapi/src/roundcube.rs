//! The parts of a mailbox that Roundcube keeps in its own database.
//!
//! The webmail in front of this API is Roundcube, and everything it knows about
//! a mailbox besides the mail itself — contacts and their groups, sender
//! identities, canned responses, the preference blob and the addresses it
//! collected on its own — lives in one SQLite file. That file is already this
//! daemon's neighbour: `Config::roundcube_db` is where the API-token lookup
//! reads from. Reading and writing those tables here means a contact added
//! through the API shows up in the webmail and vice versa, which a second store
//! of our own could not do.
//!
//! The schema is Roundcube's, so the shapes are too. A contact is stored the way
//! `rcube_contacts` stores one: the four indexed columns (`name`, `email`,
//! `firstname`, `surname`), a `vcard` column holding a vCard 3.0 string, and a
//! `words` column of folded tokens for Roundcube's own fulltext search. We write
//! all three, and build `words` with the same tokenizer Roundcube uses, so what
//! this API adds is searchable in the webmail and the other way round.
//!
//! Everything hangs off Roundcube's `users.user_id`, resolved from the mailbox
//! address. A mailbox that has never signed in to the webmail has no such row;
//! rather than invent the IMAP host Roundcube keys its users by, the operations
//! that need a row refuse and say so.

use std::path::Path;
use std::time::Duration;

use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::{ApiErr, OneOrMany};

// ---------------------------------------------------------------------------
// Connection & identity
// ---------------------------------------------------------------------------

/// Open Roundcube's database, or explain why it is not usable.
fn open(db: Option<&Path>) -> Result<Connection, ApiErr> {
    let db = db.ok_or_else(|| ApiErr::internal("this daemon has no Roundcube database configured"))?;
    if !db.exists() {
        return Err(ApiErr::not_found(
            "the Webmail has no database yet — install Webmail and sign in once",
        ));
    }
    let conn = Connection::open(db).map_err(|e| ApiErr::internal(format!("roundcube db: {e}")))?;
    // The webmail may be writing at the same instant; wait rather than fail.
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| ApiErr::internal(format!("roundcube db: {e}")))?;
    Ok(conn)
}

/// Roundcube's `user_id` for a mailbox.
///
/// The lookup is by `username` alone. Roundcube itself keys a user by
/// `(mail_host, username)`, but the IMAP host is what its login form supplied
/// and is not knowable here; usernames are the mailbox addresses and are unique
/// within an install, so the address identifies the row unambiguously.
fn user_id(conn: &Connection, email: &str) -> Result<i64, ApiErr> {
    conn.query_row(
        "SELECT user_id FROM users WHERE username = ?1 ORDER BY user_id LIMIT 1",
        [email],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| ApiErr::internal(format!("roundcube users: {e}")))?
    .ok_or_else(|| {
        ApiErr::not_found(format!(
            "{email} has no Webmail account yet — sign in to the Webmail once first"
        ))
    })
}

fn internal(e: rusqlite::Error) -> ApiErr {
    ApiErr::internal(format!("roundcube db: {e}"))
}

// ---------------------------------------------------------------------------
// Text: Roundcube's tokenizer, used for the `words` column and for search
// ---------------------------------------------------------------------------

/// Fold one character the way Roundcube's `normalize_string` folds the Latin-1
/// and Latin-2 letters it knows about; everything else lowercases.
fn fold_char(c: char) -> String {
    let lower = c.to_lowercase().next().unwrap_or(c);
    let folded = match lower {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => "a",
        'ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => "c",
        'ď' | 'đ' => "d",
        'è' | 'é' | 'ê' | 'ë' | 'ě' | 'ę' | 'ē' | 'ĕ' | 'ė' => "e",
        'ğ' | 'ĝ' | 'ġ' | 'ģ' => "g",
        'ì' | 'í' | 'î' | 'ï' | 'ī' | 'ĭ' | 'į' | 'ı' => "i",
        'ł' | 'ľ' | 'ĺ' | 'ļ' => "l",
        'ñ' | 'ń' | 'ň' | 'ņ' => "n",
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => "o",
        'ŕ' | 'ř' | 'ŗ' => "r",
        'ś' | 'š' | 'ş' | 'ŝ' | 'ș' => "s",
        'ť' | 'ţ' | 'ŧ' | 'ț' => "t",
        'ù' | 'ú' | 'û' | 'ü' | 'ů' | 'ū' | 'ŭ' | 'ű' | 'ų' => "u",
        'ý' | 'ÿ' => "y",
        'ź' | 'ž' | 'ż' => "z",
        'æ' => "ae",
        'œ' => "oe",
        'ß' => "ss",
        _ => return lower.to_string(),
    };
    folded.to_string()
}

/// Split a string into words, the way Roundcube's `tokenize_string` does: the
/// separators are whitespace and `; , " ' / + -`, and a `-`, `.` or space
/// *between two digits* joins them rather than splitting (`1-2-3` is one word).
/// Tokens shorter than `minlen` characters are dropped.
fn tokenize(text: &str, minlen: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();

    let is_sep = |c: char| c.is_whitespace() || matches!(c, ';' | ',' | '"' | '\'' | '/' | '+' | '-');

    for (i, &c) in chars.iter().enumerate() {
        // A `-`/`.`/space between digits is glue, not a break.
        let between_digits = matches!(c, '-' | '.' | ' ')
            && i > 0
            && chars[i - 1].is_ascii_digit()
            && chars.get(i + 1).is_some_and(|n| n.is_ascii_digit());
        if between_digits {
            continue;
        }
        if is_sep(c) {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }

    words
        .into_iter()
        .map(|w| fold_token(&w))
        .filter(|w| w.chars().count() >= minlen)
        .collect()
}

fn fold_token(word: &str) -> String {
    word.chars().map(fold_char).collect()
}

/// The `words` column: the folded tokens of every searchable field, deduplicated
/// in order. Roundcube searches it with a `LIKE %token%` per query token.
fn words_of(fields: &[&str]) -> String {
    let mut seen: Vec<String> = Vec::new();
    for field in fields {
        for token in tokenize(field, 2) {
            if !seen.contains(&token) {
                seen.push(token);
            }
        }
    }
    seen.join(" ")
}

// ---------------------------------------------------------------------------
// vCard 3.0 — what `contacts.vcard` holds
// ---------------------------------------------------------------------------

fn vcard_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\r' => {}
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn vcard_unescape(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') | Some('N') => out.push('\n'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split on `sep` while honouring `\;` escapes, then unescape each part.
fn vcard_split_escaped(value: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push(c);
            if let Some(next) = chars.next() {
                cur.push(next);
            }
        } else if c == sep {
            parts.push(vcard_unescape(&cur));
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    parts.push(vcard_unescape(&cur));
    parts
}

/// One logical line of a vCard: its property tag, its TYPE parameters, and value.
struct VcardLine {
    tag: String,
    types: Vec<String>,
    value: String,
}

fn vcard_lines(vcard: &str) -> Vec<VcardLine> {
    // Unfold: a line beginning with a space or tab continues the previous one.
    let mut logical: Vec<String> = Vec::new();
    for raw in vcard.split('\n') {
        let line = raw.trim_end_matches('\r');
        if (line.starts_with(' ') || line.starts_with('\t')) && !logical.is_empty() {
            logical.last_mut().unwrap().push_str(line.trim_start());
        } else {
            logical.push(line.to_string());
        }
    }

    logical
        .iter()
        .filter_map(|line| {
            let colon = line.find(':')?;
            let (prefix, value) = line.split_at(colon);
            let value = value[1..].to_string();
            let mut parts = prefix.split(';');
            let tag = parts.next().unwrap_or_default().trim().to_uppercase();
            let types = parts
                .filter_map(|p| {
                    let p = p.trim();
                    p.strip_prefix("TYPE=").or_else(|| p.strip_prefix("type=")).map(|t| {
                        t.split(',').map(|x| x.trim().to_uppercase()).collect::<Vec<_>>()
                    })
                })
                .flatten()
                .collect();
            Some(VcardLine { tag, types, value })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

/// Query string for `GET /v1/me/contacts`.
#[derive(Debug, Default, Deserialize)]
pub struct ContactQuery {
    /// Free text, matched against the same `words` Roundcube searches.
    #[serde(default)]
    pub q: Option<String>,
    /// Restrict to the members of one group.
    #[serde(default)]
    pub group: Option<i64>,
    /// `name` (default), `firstname`, `surname`, `email` or `changed`.
    #[serde(default)]
    pub sort: Option<String>,
    /// `asc` (default) or `desc`.
    #[serde(default)]
    pub order: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// The body of a contact create/update. Every field is optional; an update only
/// touches what it names.
#[derive(Debug, Default, Deserialize)]
pub struct ContactInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub firstname: Option<String>,
    #[serde(default)]
    pub surname: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub jobtitle: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub birthday: Option<String>,
    #[serde(default)]
    pub gender: Option<String>,
    #[serde(default)]
    pub street: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub zipcode: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub email: Option<OneOrMany>,
    #[serde(default)]
    pub phone: Option<OneOrMany>,
    #[serde(default)]
    pub mobile: Option<OneOrMany>,
}

#[derive(Default)]
struct Contact {
    id: i64,
    changed: String,
    name: String,
    firstname: String,
    surname: String,
    organization: String,
    jobtitle: String,
    department: String,
    website: String,
    notes: String,
    birthday: String,
    gender: String,
    street: String,
    locality: String,
    region: String,
    zipcode: String,
    country: String,
    email: Vec<String>,
    phone: Vec<String>,
    mobile: Vec<String>,
}

impl Contact {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Contact> {
        let vcard: String = row.get(6).unwrap_or_default();
        let mut contact = Contact {
            id: row.get(0)?,
            changed: row.get(1).unwrap_or_default(),
            ..Default::default()
        };
        contact.apply_vcard(&vcard);
        // The indexed columns are authoritative for the four fields they hold;
        // the vCard fills in everything else and any column left empty.
        let name: String = row.get(2).unwrap_or_default();
        if !name.is_empty() {
            contact.name = name;
        }
        let emails: String = row.get(3).unwrap_or_default();
        if !emails.trim().is_empty() {
            contact.email = split_list(&emails);
        }
        let firstname: String = row.get(4).unwrap_or_default();
        if !firstname.is_empty() {
            contact.firstname = firstname;
        }
        let surname: String = row.get(5).unwrap_or_default();
        if !surname.is_empty() {
            contact.surname = surname;
        }
        Ok(contact)
    }

    fn apply(&mut self, input: &ContactInput) {
        macro_rules! set {
            ($field:ident) => {
                if let Some(v) = &input.$field {
                    self.$field = v.clone();
                }
            };
        }
        set!(name);
        set!(firstname);
        set!(surname);
        set!(organization);
        set!(jobtitle);
        set!(department);
        set!(website);
        set!(notes);
        set!(birthday);
        set!(gender);
        set!(street);
        set!(locality);
        set!(region);
        set!(zipcode);
        set!(country);
        if let Some(v) = &input.email {
            self.email = v.clone().into_vec();
        }
        if let Some(v) = &input.phone {
            self.phone = v.clone().into_vec();
        }
        if let Some(v) = &input.mobile {
            self.mobile = v.clone().into_vec();
        }
    }

    /// The display name Roundcube would show: `name`, else "first last", else the
    /// first email.
    fn display_name(&self) -> String {
        if !self.name.is_empty() {
            return self.name.clone();
        }
        let full = format!("{} {}", self.firstname, self.surname);
        let full = full.trim();
        if !full.is_empty() {
            return full.to_string();
        }
        self.email.first().cloned().unwrap_or_default()
    }

    fn vcard(&self) -> String {
        let mut lines = vec!["BEGIN:VCARD".to_string(), "VERSION:3.0".to_string()];
        lines.push(format!(
            "N:{};{};;;",
            vcard_escape(&self.surname),
            vcard_escape(&self.firstname)
        ));
        let display = self.display_name();
        if !display.is_empty() {
            lines.push(format!("FN:{}", vcard_escape(&display)));
        }
        for (i, email) in self.email.iter().enumerate() {
            let ty = if i == 0 { "HOME" } else { "OTHER" };
            lines.push(format!("EMAIL;TYPE={ty}:{}", vcard_escape(email)));
        }
        for phone in &self.phone {
            lines.push(format!("TEL;TYPE=HOME:{}", vcard_escape(phone)));
        }
        for mobile in &self.mobile {
            lines.push(format!("TEL;TYPE=CELL:{}", vcard_escape(mobile)));
        }
        if !self.organization.is_empty() {
            lines.push(format!("ORG:{}", vcard_escape(&self.organization)));
        }
        if !self.jobtitle.is_empty() {
            lines.push(format!("TITLE:{}", vcard_escape(&self.jobtitle)));
        }
        if !self.department.is_empty() {
            lines.push(format!("X-DEPARTMENT:{}", vcard_escape(&self.department)));
        }
        if !self.website.is_empty() {
            lines.push(format!("URL:{}", vcard_escape(&self.website)));
        }
        if !self.notes.is_empty() {
            lines.push(format!("NOTE:{}", vcard_escape(&self.notes)));
        }
        if !self.birthday.is_empty() {
            lines.push(format!("BDAY:{}", vcard_escape(&self.birthday)));
        }
        if !(self.street.is_empty()
            && self.locality.is_empty()
            && self.region.is_empty()
            && self.zipcode.is_empty()
            && self.country.is_empty())
        {
            lines.push(format!(
                "ADR;TYPE=HOME:;;{};{};{};{};{}",
                vcard_escape(&self.street),
                vcard_escape(&self.locality),
                vcard_escape(&self.region),
                vcard_escape(&self.zipcode),
                vcard_escape(&self.country)
            ));
        }
        if !self.gender.is_empty() {
            lines.push(format!("X-GENDER:{}", vcard_escape(&self.gender)));
        }
        lines.push("END:VCARD".to_string());
        lines.join("\r\n")
    }

    fn apply_vcard(&mut self, vcard: &str) {
        for line in vcard_lines(vcard) {
            let value = line.value.as_str();
            match line.tag.as_str() {
                "N" => {
                    let parts = vcard_split_escaped(value, ';');
                    if let Some(surname) = parts.first() {
                        self.surname = surname.clone();
                    }
                    if let Some(firstname) = parts.get(1) {
                        self.firstname = firstname.clone();
                    }
                }
                "FN" => self.name = vcard_unescape(value),
                "EMAIL" => self.email.push(vcard_unescape(value)),
                "TEL" => {
                    let value = vcard_unescape(value);
                    if line.types.iter().any(|t| t == "CELL" || t == "IPHONE") {
                        self.mobile.push(value);
                    } else {
                        self.phone.push(value);
                    }
                }
                "ORG" => {
                    self.organization = vcard_split_escaped(value, ';')
                        .into_iter()
                        .next()
                        .unwrap_or_default()
                }
                "TITLE" => self.jobtitle = vcard_unescape(value),
                "X-DEPARTMENT" => self.department = vcard_unescape(value),
                "URL" => self.website = vcard_unescape(value),
                "NOTE" => self.notes = vcard_unescape(value),
                "BDAY" => self.birthday = vcard_unescape(value),
                "X-GENDER" => self.gender = vcard_unescape(value),
                "ADR" => {
                    let parts = vcard_split_escaped(value, ';');
                    self.street = parts.get(2).cloned().unwrap_or_default();
                    self.locality = parts.get(3).cloned().unwrap_or_default();
                    self.region = parts.get(4).cloned().unwrap_or_default();
                    self.zipcode = parts.get(5).cloned().unwrap_or_default();
                    self.country = parts.get(6).cloned().unwrap_or_default();
                }
                _ => {}
            }
        }
    }

    /// The `words` column: every fulltext field Roundcube indexes.
    fn words(&self) -> String {
        let mut fields: Vec<&str> = vec![
            &self.name,
            &self.firstname,
            &self.surname,
            &self.organization,
            &self.jobtitle,
            &self.department,
            &self.notes,
            &self.street,
            &self.locality,
            &self.region,
            &self.zipcode,
            &self.country,
            &self.website,
        ];
        for email in &self.email {
            fields.push(email);
        }
        for phone in self.phone.iter().chain(self.mobile.iter()) {
            fields.push(phone);
        }
        words_of(&fields)
    }

    fn to_json(&self, groups: Vec<i64>) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "firstname": self.firstname,
            "surname": self.surname,
            "organization": self.organization,
            "jobtitle": self.jobtitle,
            "department": self.department,
            "email": self.email,
            "phone": self.phone,
            "mobile": self.mobile,
            "street": self.street,
            "locality": self.locality,
            "region": self.region,
            "zipcode": self.zipcode,
            "country": self.country,
            "website": self.website,
            "notes": self.notes,
            "birthday": self.birthday,
            "gender": self.gender,
            "groups": groups,
            "changed": self.changed,
        })
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

const CONTACT_COLUMNS: &str =
    "contact_id, changed, name, email, firstname, surname, vcard";

fn read_contact(conn: &Connection, user: i64, id: i64) -> Result<Contact, ApiErr> {
    conn.query_row(
        &format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE contact_id = ?1 AND user_id = ?2 AND del = 0"),
        params![id, user],
        Contact::from_row,
    )
    .optional()
    .map_err(internal)?
    .ok_or_else(|| ApiErr::not_found(format!("no contact {id}")))
}

/// The group ids a contact belongs to.
fn contact_groups(conn: &Connection, id: i64) -> Result<Vec<i64>, ApiErr> {
    let mut stmt = conn
        .prepare("SELECT contactgroup_id FROM contactgroupmembers WHERE contact_id = ?1 ORDER BY contactgroup_id")
        .map_err(internal)?;
    let rows = stmt
        .query_map([id], |row| row.get::<_, i64>(0))
        .map_err(internal)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(internal)
}

/// Group ids for a page of contacts, in one query.
fn contact_groups_bulk(conn: &Connection, ids: &[i64]) -> Result<Map<String, Value>, ApiErr> {
    let mut map: Map<String, Value> = Map::new();
    if ids.is_empty() {
        return Ok(map);
    }
    let placeholders = (1..=ids.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT contact_id, contactgroup_id FROM contactgroupmembers WHERE contact_id IN ({placeholders}) ORDER BY contactgroup_id"
    );
    let mut stmt = conn.prepare(&sql).map_err(internal)?;
    let values: Vec<SqlValue> = ids.iter().map(|id| SqlValue::Integer(*id)).collect();
    let rows = stmt
        .query_map(params_from_iter(values), |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(internal)?;
    for row in rows {
        let (contact, group) = row.map_err(internal)?;
        map.entry(contact.to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("array")
            .push(json!(group));
    }
    Ok(map)
}

/// `GET /v1/me/contacts`
pub fn contacts(db: Option<&Path>, email: &str, query: &ContactQuery) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;

    let mut wheres = vec!["contacts.user_id = ?1".to_string(), "contacts.del = 0".to_string()];
    let mut values: Vec<SqlValue> = vec![SqlValue::Integer(user)];
    let mut next = 2;

    if let Some(group) = query.group {
        wheres.push(format!(
            "contacts.contact_id IN (SELECT contact_id FROM contactgroupmembers WHERE contactgroup_id = ?{next})"
        ));
        values.push(SqlValue::Integer(group));
        next += 1;
    }
    if let Some(text) = &query.q {
        for token in tokenize(text, 1) {
            wheres.push(format!("contacts.words LIKE ?{next}"));
            values.push(SqlValue::Text(format!("%{token}%")));
            next += 1;
        }
    }
    let where_clause = wheres.join(" AND ");

    let total: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM contacts WHERE {where_clause}"),
            params_from_iter(values.clone()),
            |row| row.get(0),
        )
        .map_err(internal)?;

    let (column, direction) = contact_sort(query);
    let offset = query.offset.unwrap_or(0).max(0);
    let limit = query.limit.unwrap_or(50).clamp(1, 500);

    let sql = format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts WHERE {where_clause} \
         ORDER BY contacts.{column} COLLATE NOCASE {direction}, contacts.contact_id \
         LIMIT ?{next} OFFSET ?{}",
        next + 1
    );
    values.push(SqlValue::Integer(limit));
    values.push(SqlValue::Integer(offset));

    let mut stmt = conn.prepare(&sql).map_err(internal)?;
    let contacts: Vec<Contact> = stmt
        .query_map(params_from_iter(values), Contact::from_row)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;

    let ids: Vec<i64> = contacts.iter().map(|c| c.id).collect();
    let groups = contact_groups_bulk(&conn, &ids)?;
    let contacts: Vec<Value> = contacts
        .iter()
        .map(|c| {
            let groups = groups
                .get(&c.id.to_string())
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default();
            c.to_json(groups)
        })
        .collect();

    Ok(json!({
        "email": email,
        "total": total,
        "offset": offset,
        "limit": limit,
        "sort": column,
        "order": direction.to_lowercase(),
        "contacts": contacts,
    }))
}

fn contact_sort(query: &ContactQuery) -> (&'static str, &'static str) {
    let column = match query.sort.as_deref() {
        Some("firstname") => "firstname",
        Some("surname") => "surname",
        Some("email") => "email",
        Some("changed") => "changed",
        _ => "name",
    };
    let direction = if query.order.as_deref() == Some("desc") {
        "DESC"
    } else {
        "ASC"
    };
    (column, direction)
}

/// `GET /v1/me/contacts/{id}`
pub fn contact_get(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let contact = read_contact(&conn, user, id)?;
    let groups = contact_groups(&conn, id)?;
    Ok(json!({ "email": email, "contact": contact.to_json(groups) }))
}

/// `POST /v1/me/contacts`
pub fn contact_create(db: Option<&Path>, email: &str, input: &ContactInput) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;

    let mut contact = Contact::default();
    contact.apply(input);
    if contact.display_name().is_empty() {
        return Err(ApiErr::bad("a contact needs at least a name or an email"));
    }

    conn.execute(
        "INSERT INTO contacts (user_id, changed, del, name, email, firstname, surname, vcard, words) \
         VALUES (?1, datetime('now'), 0, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            user,
            contact.display_name(),
            contact.email.join(","),
            contact.firstname,
            contact.surname,
            contact.vcard(),
            contact.words(),
        ],
    )
    .map_err(internal)?;
    let id = conn.last_insert_rowid();

    let contact = read_contact(&conn, user, id)?;
    Ok(json!({ "email": email, "contact": contact.to_json(Vec::new()) }))
}

/// `PUT /v1/me/contacts/{id}`
pub fn contact_update(
    db: Option<&Path>,
    email: &str,
    id: i64,
    input: &ContactInput,
) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let mut contact = read_contact(&conn, user, id)?;
    contact.apply(input);
    if contact.display_name().is_empty() {
        return Err(ApiErr::bad("a contact needs at least a name or an email"));
    }

    let changed = conn
        .execute(
            "UPDATE contacts SET changed = datetime('now'), name = ?3, email = ?4, firstname = ?5, \
             surname = ?6, vcard = ?7, words = ?8 WHERE contact_id = ?1 AND user_id = ?2 AND del = 0",
            params![
                id,
                user,
                contact.display_name(),
                contact.email.join(","),
                contact.firstname,
                contact.surname,
                contact.vcard(),
                contact.words(),
            ],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(ApiErr::not_found(format!("no contact {id}")));
    }

    let contact = read_contact(&conn, user, id)?;
    let groups = contact_groups(&conn, id)?;
    Ok(json!({ "email": email, "contact": contact.to_json(groups) }))
}

/// `DELETE /v1/me/contacts/{id}` — a soft delete, as Roundcube does it.
pub fn contact_delete(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let changed = conn
        .execute(
            "UPDATE contacts SET del = 1, changed = datetime('now') WHERE contact_id = ?1 AND user_id = ?2 AND del = 0",
            params![id, user],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(ApiErr::not_found(format!("no contact {id}")));
    }
    conn.execute("DELETE FROM contactgroupmembers WHERE contact_id = ?1", [id])
        .map_err(internal)?;
    Ok(json!({ "email": email, "deleted": id }))
}

// ---------------------------------------------------------------------------
// Contact groups
// ---------------------------------------------------------------------------

fn read_group(conn: &Connection, user: i64, id: i64) -> Result<(i64, String, String), ApiErr> {
    conn.query_row(
        "SELECT contactgroup_id, name, changed FROM contactgroups WHERE contactgroup_id = ?1 AND user_id = ?2 AND del = 0",
        params![id, user],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2).unwrap_or_default())),
    )
    .optional()
    .map_err(internal)?
    .ok_or_else(|| ApiErr::not_found(format!("no contact group {id}")))
}

fn group_json(id: i64, name: &str, changed: &str, members: i64) -> Value {
    json!({ "id": id, "name": name, "changed": changed, "members": members })
}

/// `GET /v1/me/contactgroups`
pub fn groups(db: Option<&Path>, email: &str) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let mut stmt = conn
        .prepare(
            "SELECT g.contactgroup_id, g.name, g.changed, \
             (SELECT COUNT(*) FROM contactgroupmembers m WHERE m.contactgroup_id = g.contactgroup_id) \
             FROM contactgroups g WHERE g.user_id = ?1 AND g.del = 0 \
             ORDER BY g.name COLLATE NOCASE, g.contactgroup_id",
        )
        .map_err(internal)?;
    let groups: Vec<Value> = stmt
        .query_map([user], |row| {
            Ok(group_json(
                row.get(0)?,
                &row.get::<_, String>(1)?,
                &row.get::<_, String>(2).unwrap_or_default(),
                row.get(3)?,
            ))
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(json!({ "email": email, "groups": groups }))
}

/// `GET /v1/me/contactgroups/{id}` — the group and the ids of its members.
pub fn group_get(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let (id, name, changed) = read_group(&conn, user, id)?;
    let members = group_members(&conn, id)?;
    let mut group = group_json(id, &name, &changed, members.len() as i64);
    group["contact_ids"] = json!(members);
    Ok(json!({ "email": email, "group": group }))
}

fn group_members(conn: &Connection, group: i64) -> Result<Vec<i64>, ApiErr> {
    let mut stmt = conn
        .prepare(
            "SELECT m.contact_id FROM contactgroupmembers m \
             JOIN contacts c ON c.contact_id = m.contact_id AND c.del = 0 \
             WHERE m.contactgroup_id = ?1 ORDER BY m.contact_id",
        )
        .map_err(internal)?;
    let rows = stmt
        .query_map([group], |row| row.get::<_, i64>(0))
        .map_err(internal)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(internal)
}

#[derive(Debug, Deserialize)]
pub struct GroupInput {
    pub name: String,
}

/// `POST /v1/me/contactgroups`
pub fn group_create(db: Option<&Path>, email: &str, input: &GroupInput) -> Result<Value, ApiErr> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiErr::bad("a group needs a name"));
    }
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    conn.execute(
        "INSERT INTO contactgroups (user_id, changed, del, name) VALUES (?1, datetime('now'), 0, ?2)",
        params![user, name],
    )
    .map_err(internal)?;
    let id = conn.last_insert_rowid();
    let (id, name, changed) = read_group(&conn, user, id)?;
    Ok(json!({ "email": email, "group": group_json(id, &name, &changed, 0) }))
}

/// `PUT /v1/me/contactgroups/{id}` — rename.
pub fn group_update(
    db: Option<&Path>,
    email: &str,
    id: i64,
    input: &GroupInput,
) -> Result<Value, ApiErr> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(ApiErr::bad("a group needs a name"));
    }
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let changed = conn
        .execute(
            "UPDATE contactgroups SET name = ?3, changed = datetime('now') \
             WHERE contactgroup_id = ?1 AND user_id = ?2 AND del = 0",
            params![id, user, name],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(ApiErr::not_found(format!("no contact group {id}")));
    }
    let (id, name, changed) = read_group(&conn, user, id)?;
    let members = group_members(&conn, id)?.len() as i64;
    Ok(json!({ "email": email, "group": group_json(id, &name, &changed, members) }))
}

/// `DELETE /v1/me/contactgroups/{id}`
pub fn group_delete(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let changed = conn
        .execute(
            "UPDATE contactgroups SET del = 1, changed = datetime('now') \
             WHERE contactgroup_id = ?1 AND user_id = ?2 AND del = 0",
            params![id, user],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(ApiErr::not_found(format!("no contact group {id}")));
    }
    conn.execute(
        "DELETE FROM contactgroupmembers WHERE contactgroup_id = ?1",
        [id],
    )
    .map_err(internal)?;
    Ok(json!({ "email": email, "deleted": id }))
}

#[derive(Debug, Deserialize)]
pub struct GroupMembers {
    pub contact_ids: Vec<i64>,
}

/// `PUT /v1/me/contactgroups/{id}/contacts` — replace the membership wholesale.
pub fn group_set_members(
    db: Option<&Path>,
    email: &str,
    id: i64,
    body: &GroupMembers,
) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    read_group(&conn, user, id)?;

    conn.execute(
        "DELETE FROM contactgroupmembers WHERE contactgroup_id = ?1",
        [id],
    )
    .map_err(internal)?;
    for contact in &body.contact_ids {
        // Only accept contacts this mailbox actually owns.
        let owned: Option<i64> = conn
            .query_row(
                "SELECT contact_id FROM contacts WHERE contact_id = ?1 AND user_id = ?2 AND del = 0",
                params![contact, user],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        if owned.is_none() {
            return Err(ApiErr::bad(format!("no contact {contact}")));
        }
        conn.execute(
            "INSERT OR IGNORE INTO contactgroupmembers (contactgroup_id, contact_id, created) \
             VALUES (?1, ?2, datetime('now'))",
            params![id, contact],
        )
        .map_err(internal)?;
    }

    let (id, name, changed) = read_group(&conn, user, id)?;
    let members = group_members(&conn, id)?;
    let mut group = group_json(id, &name, &changed, members.len() as i64);
    group["contact_ids"] = json!(members);
    Ok(json!({ "email": email, "group": group }))
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct IdentityInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub bcc: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub html_signature: Option<bool>,
    #[serde(default)]
    pub standard: Option<bool>,
}

const IDENTITY_COLUMNS: &str =
    "identity_id, changed, standard, name, organization, email, \"reply-to\", bcc, signature, html_signature";

fn identity_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "changed": row.get::<_, String>(1).unwrap_or_default(),
        "standard": row.get::<_, i64>(2).unwrap_or(0) != 0,
        "name": row.get::<_, String>(3).unwrap_or_default(),
        "organization": row.get::<_, String>(4).unwrap_or_default(),
        "email": row.get::<_, String>(5).unwrap_or_default(),
        "reply_to": row.get::<_, String>(6).unwrap_or_default(),
        "bcc": row.get::<_, String>(7).unwrap_or_default(),
        "signature": row.get::<_, String>(8).unwrap_or_default(),
        "html_signature": row.get::<_, i64>(9).unwrap_or(0) != 0,
    }))
}

fn read_identity(conn: &Connection, user: i64, id: i64) -> Result<Value, ApiErr> {
    conn.query_row(
        &format!(
            "SELECT {IDENTITY_COLUMNS} FROM identities WHERE identity_id = ?1 AND user_id = ?2 AND del <> 1"
        ),
        params![id, user],
        identity_json,
    )
    .optional()
    .map_err(internal)?
    .ok_or_else(|| ApiErr::not_found(format!("no identity {id}")))
}

/// `GET /v1/me/identities`
pub fn identities(db: Option<&Path>, email: &str) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {IDENTITY_COLUMNS} FROM identities WHERE user_id = ?1 AND del <> 1 \
             ORDER BY standard DESC, name COLLATE NOCASE, identity_id"
        ))
        .map_err(internal)?;
    let identities: Vec<Value> = stmt
        .query_map([user], identity_json)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(json!({ "email": email, "identities": identities }))
}

/// `POST /v1/me/identities`
pub fn identity_create(
    db: Option<&Path>,
    email: &str,
    input: &IdentityInput,
) -> Result<Value, ApiErr> {
    let identity_email = input
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiErr::bad("an identity needs an email address"))?
        .to_string();

    let conn = open(db)?;
    let user = user_id(&conn, email)?;

    let existing: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM identities WHERE user_id = ?1 AND del <> 1",
            [user],
            |row| row.get(0),
        )
        .map_err(internal)?;
    // Roundcube makes the first identity the standard one, and honours an
    // explicit request for a later one.
    let standard = input.standard.unwrap_or(false) || existing == 0;

    conn.execute(
        "INSERT INTO identities (user_id, changed, del, standard, name, organization, email, \
         \"reply-to\", bcc, signature, html_signature) \
         VALUES (?1, datetime('now'), 0, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            user,
            standard as i64,
            input.name.clone().unwrap_or_default(),
            input.organization.clone().unwrap_or_default(),
            identity_email,
            input.reply_to.clone().unwrap_or_default(),
            input.bcc.clone().unwrap_or_default(),
            input.signature.clone().unwrap_or_default(),
            input.html_signature.unwrap_or(false) as i64,
        ],
    )
    .map_err(internal)?;
    let id = conn.last_insert_rowid();
    if standard {
        make_standard(&conn, user, id)?;
    }

    Ok(json!({ "email": email, "identity": read_identity(&conn, user, id)? }))
}

/// `PUT /v1/me/identities/{id}`
pub fn identity_update(
    db: Option<&Path>,
    email: &str,
    id: i64,
    input: &IdentityInput,
) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let existing = read_identity(&conn, user, id)?;

    let pick = |new: &Option<String>, key: &str| {
        new.clone()
            .unwrap_or_else(|| existing[key].as_str().unwrap_or_default().to_string())
    };
    let identity_email = pick(&input.email, "email");
    if identity_email.trim().is_empty() {
        return Err(ApiErr::bad("an identity needs an email address"));
    }
    let html = input
        .html_signature
        .unwrap_or_else(|| existing["html_signature"].as_bool().unwrap_or(false));

    conn.execute(
        "UPDATE identities SET changed = datetime('now'), name = ?3, organization = ?4, email = ?5, \
         \"reply-to\" = ?6, bcc = ?7, signature = ?8, html_signature = ?9 \
         WHERE identity_id = ?1 AND user_id = ?2 AND del <> 1",
        params![
            id,
            user,
            pick(&input.name, "name"),
            pick(&input.organization, "organization"),
            identity_email,
            pick(&input.reply_to, "reply_to"),
            pick(&input.bcc, "bcc"),
            pick(&input.signature, "signature"),
            html as i64,
        ],
    )
    .map_err(internal)?;
    if input.standard == Some(true) {
        make_standard(&conn, user, id)?;
    }
    Ok(json!({ "email": email, "identity": read_identity(&conn, user, id)? }))
}

/// `DELETE /v1/me/identities/{id}` — a soft delete, but never the last one.
pub fn identity_delete(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let existing = read_identity(&conn, user, id)?;

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM identities WHERE user_id = ?1 AND del <> 1",
            [user],
            |row| row.get(0),
        )
        .map_err(internal)?;
    if count <= 1 {
        return Err(ApiErr::bad(
            "cannot delete the only identity — every mailbox needs one",
        ));
    }

    conn.execute(
        "UPDATE identities SET del = 1, standard = 0, changed = datetime('now') \
         WHERE identity_id = ?1 AND user_id = ?2",
        params![id, user],
    )
    .map_err(internal)?;
    // Deleting the standard identity should leave one behind.
    if existing["standard"].as_bool().unwrap_or(false) {
        let next: Option<i64> = conn
            .query_row(
                "SELECT identity_id FROM identities WHERE user_id = ?1 AND del <> 1 \
                 ORDER BY identity_id LIMIT 1",
                [user],
                |row| row.get(0),
            )
            .optional()
            .map_err(internal)?;
        if let Some(next) = next {
            make_standard(&conn, user, next)?;
        }
    }
    Ok(json!({ "email": email, "deleted": id }))
}

fn make_standard(conn: &Connection, user: i64, id: i64) -> Result<(), ApiErr> {
    conn.execute(
        "UPDATE identities SET standard = 0 WHERE user_id = ?1 AND identity_id <> ?2",
        params![user, id],
    )
    .map_err(internal)?;
    conn.execute(
        "UPDATE identities SET standard = 1 WHERE identity_id = ?1 AND user_id = ?2",
        params![id, user],
    )
    .map_err(internal)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Canned responses
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct ResponseInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub is_html: Option<bool>,
}

fn response_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "changed": row.get::<_, String>(1).unwrap_or_default(),
        "name": row.get::<_, String>(2).unwrap_or_default(),
        "data": row.get::<_, String>(3).unwrap_or_default(),
        "is_html": row.get::<_, i64>(4).unwrap_or(0) != 0,
    }))
}

fn read_response(conn: &Connection, user: i64, id: i64) -> Result<Value, ApiErr> {
    conn.query_row(
        "SELECT response_id, changed, name, data, is_html FROM responses \
         WHERE response_id = ?1 AND user_id = ?2 AND del <> 1",
        params![id, user],
        response_json,
    )
    .optional()
    .map_err(internal)?
    .ok_or_else(|| ApiErr::not_found(format!("no response {id}")))
}

/// `GET /v1/me/responses`
pub fn responses(db: Option<&Path>, email: &str) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let mut stmt = conn
        .prepare(
            "SELECT response_id, changed, name, data, is_html FROM responses \
             WHERE user_id = ?1 AND del <> 1 ORDER BY name COLLATE NOCASE, response_id",
        )
        .map_err(internal)?;
    let responses: Vec<Value> = stmt
        .query_map([user], response_json)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(json!({ "email": email, "responses": responses }))
}

/// `POST /v1/me/responses`
pub fn response_create(
    db: Option<&Path>,
    email: &str,
    input: &ResponseInput,
) -> Result<Value, ApiErr> {
    let name = input
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiErr::bad("a response needs a name"))?;
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    conn.execute(
        "INSERT INTO responses (user_id, changed, del, name, data, is_html) \
         VALUES (?1, datetime('now'), 0, ?2, ?3, ?4)",
        params![
            user,
            name,
            input.data.clone().unwrap_or_default(),
            input.is_html.unwrap_or(false) as i64,
        ],
    )
    .map_err(internal)?;
    let id = conn.last_insert_rowid();
    Ok(json!({ "email": email, "response": read_response(&conn, user, id)? }))
}

/// `PUT /v1/me/responses/{id}`
pub fn response_update(
    db: Option<&Path>,
    email: &str,
    id: i64,
    input: &ResponseInput,
) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let existing = read_response(&conn, user, id)?;
    let name = input
        .name
        .clone()
        .unwrap_or_else(|| existing["name"].as_str().unwrap_or_default().to_string());
    if name.trim().is_empty() {
        return Err(ApiErr::bad("a response needs a name"));
    }
    let data = input
        .data
        .clone()
        .unwrap_or_else(|| existing["data"].as_str().unwrap_or_default().to_string());
    let is_html = input
        .is_html
        .unwrap_or_else(|| existing["is_html"].as_bool().unwrap_or(false));

    conn.execute(
        "UPDATE responses SET changed = datetime('now'), name = ?3, data = ?4, is_html = ?5 \
         WHERE response_id = ?1 AND user_id = ?2 AND del <> 1",
        params![id, user, name, data, is_html as i64],
    )
    .map_err(internal)?;
    Ok(json!({ "email": email, "response": read_response(&conn, user, id)? }))
}

/// `DELETE /v1/me/responses/{id}`
pub fn response_delete(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let changed = conn
        .execute(
            "UPDATE responses SET del = 1, changed = datetime('now') \
             WHERE response_id = ?1 AND user_id = ?2 AND del <> 1",
            params![id, user],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(ApiErr::not_found(format!("no response {id}")));
    }
    Ok(json!({ "email": email, "deleted": id }))
}

// ---------------------------------------------------------------------------
// Preferences — Roundcube's PHP-serialized blob
// ---------------------------------------------------------------------------

/// `GET /v1/me/settings` — the decoded preference blob.
pub fn preferences_get(db: Option<&Path>, email: &str) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let raw: Option<String> = conn
        .query_row("SELECT preferences FROM users WHERE user_id = ?1", [user], |row| {
            row.get(0)
        })
        .optional()
        .map_err(internal)?
        .flatten();
    let prefs = match raw.as_deref() {
        None | Some("") => Value::Object(Map::new()),
        Some(text) => php_decode(text).ok_or_else(|| {
            ApiErr::internal("the Webmail's preferences are in a format this API cannot read")
        })?,
    };
    Ok(json!({ "email": email, "preferences": prefs }))
}

/// `PUT /v1/me/settings` — merge the named preferences, leaving the rest alone.
pub fn preferences_put(
    db: Option<&Path>,
    email: &str,
    patch: &Map<String, Value>,
) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let raw: Option<String> = conn
        .query_row("SELECT preferences FROM users WHERE user_id = ?1", [user], |row| {
            row.get(0)
        })
        .optional()
        .map_err(internal)?
        .flatten();

    let mut prefs = match raw.as_deref() {
        None | Some("") => Value::Object(Map::new()),
        Some(text) => php_decode(text).ok_or_else(|| {
            ApiErr::internal("the Webmail's preferences are in a format this API cannot edit safely")
        })?,
    };
    if !prefs.is_object() {
        prefs = Value::Object(Map::new());
    }
    let object = prefs.as_object_mut().expect("object");
    for (key, value) in patch {
        if value.is_null() {
            object.remove(key);
        } else {
            object.insert(key.clone(), value.clone());
        }
    }

    let mut encoded = String::new();
    php_encode(&prefs, &mut encoded);
    conn.execute(
        "UPDATE users SET preferences = ?2 WHERE user_id = ?1",
        params![user, encoded],
    )
    .map_err(internal)?;

    Ok(json!({ "email": email, "preferences": prefs }))
}

/// Decode one PHP `serialize()` value. Only the shapes Roundcube's preferences
/// actually use are understood: scalars, and arrays of them.
fn php_decode(input: &str) -> Option<Value> {
    struct Parser<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl Parser<'_> {
        fn byte(&mut self) -> Option<u8> {
            let b = *self.bytes.get(self.at)?;
            self.at += 1;
            Some(b)
        }
        fn expect(&mut self, c: u8) -> Option<()> {
            (self.byte()? == c).then_some(())
        }
        fn number_until(&mut self, end: u8) -> Option<&str> {
            let start = self.at;
            while *self.bytes.get(self.at)? != end {
                self.at += 1;
            }
            let text = std::str::from_utf8(&self.bytes[start..self.at]).ok()?;
            self.at += 1;
            Some(text)
        }
        fn value(&mut self) -> Option<Value> {
            match self.byte()? {
                b'N' => {
                    self.expect(b';')?;
                    Some(Value::Null)
                }
                b'b' => {
                    self.expect(b':')?;
                    let v = self.byte()? == b'1';
                    self.expect(b';')?;
                    Some(Value::Bool(v))
                }
                b'i' => {
                    self.expect(b':')?;
                    let n: i64 = self.number_until(b';')?.parse().ok()?;
                    Some(json!(n))
                }
                b'd' => {
                    self.expect(b':')?;
                    let text = self.number_until(b';')?;
                    let f: f64 = if text == "NAN" {
                        f64::NAN
                    } else if text == "INF" {
                        f64::INFINITY
                    } else if text == "-INF" {
                        f64::NEG_INFINITY
                    } else {
                        text.parse().ok()?
                    };
                    serde_json::Number::from_f64(f).map(Value::Number)
                }
                b's' => {
                    self.expect(b':')?;
                    let len: usize = self.number_until(b':')?.parse().ok()?;
                    self.expect(b'"')?;
                    let text = std::str::from_utf8(self.bytes.get(self.at..self.at + len)?)
                        .ok()?
                        .to_string();
                    self.at += len;
                    self.expect(b'"')?;
                    self.expect(b';')?;
                    Some(Value::String(text))
                }
                b'a' => {
                    self.expect(b':')?;
                    let count: usize = self.number_until(b':')?.parse().ok()?;
                    self.expect(b'{')?;
                    let mut map = Map::new();
                    let mut list = true;
                    for i in 0..count {
                        let key = self.value()?;
                        if key.as_i64() != Some(i as i64) {
                            list = false;
                        }
                        let key = match key {
                            Value::String(s) => s,
                            Value::Number(n) => n.to_string(),
                            _ => return None,
                        };
                        map.insert(key, self.value()?);
                    }
                    self.expect(b'}')?;
                    if list {
                        let items: Vec<Value> = (0..count)
                            .map(|i| map.get(&i.to_string()).cloned().unwrap_or(Value::Null))
                            .collect();
                        Some(Value::Array(items))
                    } else {
                        Some(Value::Object(map))
                    }
                }
                _ => None,
            }
        }
    }

    let mut parser = Parser {
        bytes: input.as_bytes(),
        at: 0,
    };
    let value = parser.value()?;
    (parser.at == parser.bytes.len()).then_some(value)
}

/// Encode a value back into PHP `serialize()` form.
fn php_encode(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("N;"),
        Value::Bool(true) => out.push_str("b:1;"),
        Value::Bool(false) => out.push_str("b:0;"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&format!("i:{i};"));
            } else {
                out.push_str(&format!("d:{};", n.as_f64().unwrap_or(0.0)));
            }
        }
        Value::String(s) => out.push_str(&format!("s:{}:\"{}\";", s.len(), s)),
        Value::Array(items) => {
            out.push_str(&format!("a:{}:{{", items.len()));
            for (i, item) in items.iter().enumerate() {
                out.push_str(&format!("i:{i};"));
                php_encode(item, out);
            }
            out.push('}');
        }
        Value::Object(map) => {
            out.push_str(&format!("a:{}:{{", map.len()));
            for (key, item) in map {
                out.push_str(&format!("s:{}:\"{}\";", key.len(), key));
                php_encode(item, out);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------------------
// Collected addresses
// ---------------------------------------------------------------------------

/// `GET /v1/me/collected-addresses?type=1`
///
/// The addresses Roundcube saved on its own: `type` 1 for the recipients of mail
/// you sent, 2 for the senders of mail you trusted.
pub fn collected(db: Option<&Path>, email: &str, kind: Option<i64>) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let mut values: Vec<SqlValue> = vec![SqlValue::Integer(user)];
    let mut where_clause = "user_id = ?1".to_string();
    if let Some(kind) = kind {
        where_clause.push_str(" AND \"type\" = ?2");
        values.push(SqlValue::Integer(kind));
    }
    let mut stmt = conn
        .prepare(&format!(
            "SELECT address_id, changed, name, email, \"type\" FROM collected_addresses \
             WHERE {where_clause} ORDER BY name COLLATE NOCASE, email"
        ))
        .map_err(internal)?;
    let addresses: Vec<Value> = stmt
        .query_map(params_from_iter(values), |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "changed": row.get::<_, String>(1).unwrap_or_default(),
                "name": row.get::<_, String>(2).unwrap_or_default(),
                "email": row.get::<_, String>(3).unwrap_or_default(),
                "type": row.get::<_, i64>(4).unwrap_or(0),
            }))
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(json!({
        "email": email,
        "total": addresses.len(),
        "addresses": addresses,
    }))
}

/// `DELETE /v1/me/collected-addresses/{id}` — Roundcube deletes these outright.
pub fn collected_delete(db: Option<&Path>, email: &str, id: i64) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let changed = conn
        .execute(
            "DELETE FROM collected_addresses WHERE address_id = ?1 AND user_id = ?2",
            params![id, user],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(ApiErr::not_found(format!("no collected address {id}")));
    }
    Ok(json!({ "email": email, "deleted": id }))
}

// ---------------------------------------------------------------------------
// Autocomplete
// ---------------------------------------------------------------------------

/// `GET /v1/me/autocomplete?q=jane`
///
/// Contacts first, then collected addresses, deduplicated by address — what the
/// webmail's own recipient field would offer.
pub fn autocomplete(db: Option<&Path>, email: &str, query: &str) -> Result<Value, ApiErr> {
    let conn = open(db)?;
    let user = user_id(&conn, email)?;
    let tokens = tokenize(query, 1);

    let mut suggestions: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    if !tokens.is_empty() {
        let mut wheres = vec!["user_id = ?1".to_string(), "del = 0".to_string()];
        let mut values: Vec<SqlValue> = vec![SqlValue::Integer(user)];
        for (i, token) in tokens.iter().enumerate() {
            wheres.push(format!("words LIKE ?{}", i + 2));
            values.push(SqlValue::Text(format!("%{token}%")));
        }
        let mut stmt = conn
            .prepare(&format!(
                "SELECT name, email FROM contacts WHERE {} ORDER BY name COLLATE NOCASE LIMIT 20",
                wheres.join(" AND ")
            ))
            .map_err(internal)?;
        let rows = stmt
            .query_map(params_from_iter(values), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(internal)?;
        for row in rows {
            let (name, emails) = row.map_err(internal)?;
            for address in split_list(&emails) {
                let key = address.to_lowercase();
                if seen.contains(&key) {
                    continue;
                }
                seen.push(key);
                suggestions.push(json!({ "name": name, "email": address, "source": "contact" }));
            }
        }
    }

    if !tokens.is_empty() {
        let pattern = format!("%{}%", tokens.join("%"));
        let mut stmt = conn
            .prepare(
                "SELECT name, email FROM collected_addresses WHERE user_id = ?1 \
                 AND (lower(name) LIKE ?2 OR lower(email) LIKE ?2) \
                 ORDER BY name COLLATE NOCASE LIMIT 20",
            )
            .map_err(internal)?;
        let rows = stmt
            .query_map(params![user, pattern], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(internal)?;
        for row in rows {
            let (name, address) = row.map_err(internal)?;
            let key = address.to_lowercase();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            suggestions.push(json!({ "name": name, "email": address, "source": "collected" }));
        }
    }

    Ok(json!({
        "email": email,
        "q": query,
        "suggestions": suggestions,
    }))
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcard_round_trips_through_the_parser() {
        let mut contact = Contact::default();
        contact.name = "Jane Doe".into();
        contact.firstname = "Jane".into();
        contact.surname = "Doe".into();
        contact.organization = "Acme; Inc".into();
        contact.jobtitle = "CEO".into();
        contact.department = "Sales".into();
        contact.website = "https://acme.example".into();
        contact.notes = "Met at a conference\nsecond line".into();
        contact.birthday = "1980-01-02".into();
        contact.gender = "F".into();
        contact.email = vec!["jane@acme.example".into(), "jd@acme.example".into()];
        contact.phone = vec!["+62 21 555".into()];
        contact.mobile = vec!["+62 811 555".into()];
        contact.street = "1 Main St".into();
        contact.locality = "Jakarta".into();
        contact.region = "DKI".into();
        contact.zipcode = "10110".into();
        contact.country = "Indonesia".into();

        let mut parsed = Contact::default();
        parsed.apply_vcard(&contact.vcard());

        assert_eq!(parsed.name, "Jane Doe");
        assert_eq!(parsed.firstname, "Jane");
        assert_eq!(parsed.surname, "Doe");
        assert_eq!(parsed.organization, "Acme; Inc");
        assert_eq!(parsed.jobtitle, "CEO");
        assert_eq!(parsed.department, "Sales");
        assert_eq!(parsed.website, "https://acme.example");
        assert_eq!(parsed.notes, "Met at a conference\nsecond line");
        assert_eq!(parsed.birthday, "1980-01-02");
        assert_eq!(parsed.email, contact.email);
        assert_eq!(parsed.phone, contact.phone);
        assert_eq!(parsed.mobile, contact.mobile);
        assert_eq!(parsed.street, "1 Main St");
        assert_eq!(parsed.locality, "Jakarta");
        assert_eq!(parsed.region, "DKI");
        assert_eq!(parsed.zipcode, "10110");
        assert_eq!(parsed.country, "Indonesia");
        assert_eq!(contact.display_name(), "Jane Doe");
    }

    #[test]
    fn fold_marks_between_digits_are_not_separators() {
        assert_eq!(tokenize("1-2-3", 2), vec!["123"]);
        assert_eq!(tokenize("1.5", 2), vec!["15"]);
    }

    #[test]
    fn words_are_folded_and_deduplicated() {
        let words = words_of(&["José Núñez", "José Núñez"]);
        assert!(words.contains("jose"));
        assert!(words.contains("nunez"));
        assert_eq!(words.split(' ').filter(|w| *w == "jose").count(), 1);
    }

    #[test]
    fn php_round_trips_scalars_and_nested_arrays() {
        let original = "a:3:{s:8:\"language\";s:2:\"en\";s:4:\"page\";i:2;\
                        s:4:\"list\";a:2:{i:0;s:1:\"a\";i:1;s:1:\"b\";}}";
        let decoded = php_decode(original).expect("decodes");
        assert_eq!(decoded["language"], "en");
        assert_eq!(decoded["page"], 2);
        assert_eq!(decoded["list"], json!(["a", "b"]));

        let mut reencoded = String::new();
        php_encode(&decoded, &mut reencoded);
        assert_eq!(php_decode(&reencoded).unwrap(), decoded);
    }

    #[test]
    fn php_refuses_what_it_cannot_read() {
        assert!(php_decode("O:8:\"stdClass\":0:{}").is_none());
        assert!(php_decode("a:1:{s:1:\"x\";i:1;}").is_some());
    }

    // -- End-to-end against a throwaway copy of Roundcube's schema -------------

    /// A private SQLite file carrying the tables these functions touch, with one
    /// user in it. Returns the path and the mailbox address it holds.
    fn fixture() -> (std::path::PathBuf, String) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "dockpanel-roundcube-test-{}-{unique}.db",
            std::process::id()
        ));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE users (user_id integer NOT NULL PRIMARY KEY, username varchar(128) NOT NULL, \
               mail_host varchar(128) NOT NULL default '', language varchar(5), preferences text);
             CREATE TABLE contacts (contact_id integer NOT NULL PRIMARY KEY, user_id integer NOT NULL, \
               changed datetime NOT NULL, del tinyint NOT NULL default 0, name varchar(128) NOT NULL default '', \
               email text NOT NULL default '', firstname varchar(128) NOT NULL default '', \
               surname varchar(128) NOT NULL default '', vcard text NOT NULL default '', words text NOT NULL default '');
             CREATE TABLE contactgroups (contactgroup_id integer NOT NULL PRIMARY KEY, user_id integer NOT NULL, \
               changed datetime NOT NULL, del tinyint NOT NULL default 0, name varchar(128) NOT NULL default '');
             CREATE TABLE contactgroupmembers (contactgroup_id integer NOT NULL, contact_id integer NOT NULL, \
               created datetime NOT NULL, PRIMARY KEY (contactgroup_id, contact_id));
             CREATE TABLE identities (identity_id integer NOT NULL PRIMARY KEY, user_id integer NOT NULL, \
               changed datetime NOT NULL, del tinyint NOT NULL default 0, standard tinyint NOT NULL default 0, \
               name varchar(128) NOT NULL default '', organization varchar(128) NOT NULL default '', \
               email varchar(128) NOT NULL default '', \"reply-to\" varchar(128) NOT NULL default '', \
               bcc varchar(128) NOT NULL default '', signature text, html_signature tinyint NOT NULL default 0);
             CREATE TABLE responses (response_id integer NOT NULL PRIMARY KEY, user_id integer NOT NULL, \
               changed datetime NOT NULL, del tinyint NOT NULL default 0, name varchar(255) NOT NULL, \
               data text NOT NULL, is_html tinyint NOT NULL default 0);
             CREATE TABLE collected_addresses (address_id integer NOT NULL PRIMARY KEY, user_id integer NOT NULL, \
               changed datetime NOT NULL, name varchar(255) NOT NULL default '', email varchar(255) NOT NULL, \
               \"type\" integer NOT NULL);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (user_id, username, mail_host) VALUES (1, 'me@example.com', 'imap.example.com')",
            [],
        )
        .unwrap();
        drop(conn);
        (path, "me@example.com".to_string())
    }

    fn lists(value: &Value, key: &str) -> Vec<i64> {
        value[key]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_i64).collect())
            .unwrap_or_default()
    }

    #[test]
    fn address_book_round_trips_through_the_schema() {
        let (path, email) = fixture();
        let db = Some(path.as_path());

        let created = contact_create(
            db,
            &email,
            &ContactInput {
                name: Some("Jane Doe".into()),
                email: Some(OneOrMany::Many(vec![
                    "jane@x.example".into(),
                    "jd@x.example".into(),
                ])),
                phone: Some(OneOrMany::One("+62 21 555".into())),
                notes: Some("met at a conference".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let id = created["contact"]["id"].as_i64().unwrap();
        assert_eq!(created["contact"]["email"], json!(["jane@x.example", "jd@x.example"]));

        // Searchable by the same folded words Roundcube writes.
        let found = contacts(
            db,
            &email,
            &ContactQuery {
                q: Some("Jane".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(found["total"], 1);
        assert_eq!(found["contacts"][0]["id"], id);

        // A partial update leaves the untouched fields alone.
        contact_update(
            db,
            &email,
            id,
            &ContactInput {
                jobtitle: Some("CTO".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let got = contact_get(db, &email, id).unwrap();
        assert_eq!(got["contact"]["jobtitle"], "CTO");
        assert_eq!(got["contact"]["name"], "Jane Doe");
        assert_eq!(got["contact"]["phone"], json!(["+62 21 555"]));

        // Groups and membership.
        let group = group_create(
            db,
            &email,
            &GroupInput {
                name: "Friends".into(),
            },
        )
        .unwrap();
        let gid = group["group"]["id"].as_i64().unwrap();
        group_set_members(
            db,
            &email,
            gid,
            &GroupMembers {
                contact_ids: vec![id],
            },
        )
        .unwrap();
        let group = group_get(db, &email, gid).unwrap();
        assert_eq!(group["group"]["contact_ids"], json!([id]));
        assert_eq!(group["group"]["members"], 1);

        let in_group = contacts(
            db,
            &email,
            &ContactQuery {
                group: Some(gid),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(in_group["total"], 1);
        assert_eq!(lists(&in_group["contacts"][0], "groups"), vec![gid]);

        // A group cannot borrow a contact the mailbox does not own.
        assert!(group_set_members(
            db,
            &email,
            gid,
            &GroupMembers {
                contact_ids: vec![9999],
            },
        )
        .is_err());
        group_set_members(
            db,
            &email,
            gid,
            &GroupMembers {
                contact_ids: vec![id],
            },
        )
        .unwrap();

        // Delete is a soft delete: the row stays, but stops being visible.
        contact_delete(db, &email, id).unwrap();
        assert!(contact_get(db, &email, id).is_err());
        let listed = contacts(db, &email, &ContactQuery::default()).unwrap();
        assert_eq!(listed["total"], 0);
        group_delete(db, &email, gid).unwrap();
        assert!(group_get(db, &email, gid).is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn identities_keep_exactly_one_standard() {
        let (path, email) = fixture();
        let db = Some(path.as_path());

        let first = identity_create(
            db,
            &email,
            &IdentityInput {
                email: Some(email.clone()),
                name: Some("Me".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let first_id = first["identity"]["id"].as_i64().unwrap();
        assert_eq!(first["identity"]["standard"], true);

        let second = identity_create(
            db,
            &email,
            &IdentityInput {
                email: Some("alias@example.com".into()),
                standard: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let second_id = second["identity"]["id"].as_i64().unwrap();
        assert_eq!(second["identity"]["standard"], true);

        let all = identities(db, &email).unwrap();
        let standards = all["identities"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["standard"] == true)
            .count();
        assert_eq!(standards, 1);

        // Deleting the standard hands the role to the survivor.
        identity_delete(db, &email, second_id).unwrap();
        let after = identities(db, &email).unwrap();
        let got = after["identities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == first_id)
            .cloned()
            .unwrap();
        assert_eq!(got["standard"], true);

        // The last identity cannot be removed.
        assert!(identity_delete(db, &email, first_id).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn responses_crud() {
        let (path, email) = fixture();
        let db = Some(path.as_path());

        let created = response_create(
            db,
            &email,
            &ResponseInput {
                name: Some("Thanks".into()),
                data: Some("Thank you!".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let id = created["response"]["id"].as_i64().unwrap();

        response_update(
            db,
            &email,
            id,
            &ResponseInput {
                is_html: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let got = responses(db, &email).unwrap();
        assert_eq!(got["responses"][0]["name"], "Thanks");
        assert_eq!(got["responses"][0]["is_html"], true);
        assert_eq!(got["responses"][0]["data"], "Thank you!");

        response_delete(db, &email, id).unwrap();
        assert_eq!(responses(db, &email).unwrap()["responses"], json!([]));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn preferences_merge_and_preserve_unknown_keys() {
        let (path, email) = fixture();
        let db = Some(path.as_path());

        // Seed a blob with a key the API does not know about.
        {
            let conn = open(db).unwrap();
            conn.execute(
                "UPDATE users SET preferences = ?1 WHERE user_id = 1",
                ["a:1:{s:11:\"client_hash\";s:4:\"abcd\";}"],
            )
            .unwrap();
        }

        let mut patch = Map::new();
        patch.insert("language".into(), json!("id"));
        patch.insert("pagesize".into(), json!(25));
        preferences_put(db, &email, &patch).unwrap();

        let got = preferences_get(db, &email).unwrap();
        assert_eq!(got["preferences"]["language"], "id");
        assert_eq!(got["preferences"]["pagesize"], 25);
        assert_eq!(got["preferences"]["client_hash"], "abcd");

        // A null removes a key.
        let mut remove = Map::new();
        remove.insert("pagesize".into(), Value::Null);
        let got = preferences_put(db, &email, &remove).unwrap();
        assert!(got["preferences"].get("pagesize").is_none());
        assert_eq!(got["preferences"]["client_hash"], "abcd");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn collected_addresses_list_and_delete() {
        let (path, email) = fixture();
        let db = Some(path.as_path());
        {
            let conn = open(db).unwrap();
            conn.execute(
                "INSERT INTO collected_addresses (user_id, changed, name, email, \"type\") \
                 VALUES (1, datetime('now'), 'Bob', 'bob@x.example', 1), \
                        (1, datetime('now'), 'Carol', 'carol@x.example', 2)",
                [],
            )
            .unwrap();
        }

        let all = collected(db, &email, None).unwrap();
        assert_eq!(all["total"], 2);
        let recipients = collected(db, &email, Some(1)).unwrap();
        assert_eq!(recipients["total"], 1);
        assert_eq!(recipients["addresses"][0]["name"], "Bob");

        let id = all["addresses"][0]["id"].as_i64().unwrap();
        collected_delete(db, &email, id).unwrap();
        assert_eq!(collected(db, &email, None).unwrap()["total"], 1);

        let suggestions = autocomplete(db, &email, "carol").unwrap();
        assert_eq!(suggestions["suggestions"][0]["email"], "carol@x.example");
        assert_eq!(suggestions["suggestions"][0]["source"], "collected");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_mailbox_without_a_webmail_account_is_told_so() {
        let (path, _) = fixture();
        let db = Some(path.as_path());
        let err = contacts(db, "stranger@example.com", &ContactQuery::default()).unwrap_err();
        assert_eq!(err.0, axum::http::StatusCode::NOT_FOUND);
        std::fs::remove_file(&path).ok();
    }
}
