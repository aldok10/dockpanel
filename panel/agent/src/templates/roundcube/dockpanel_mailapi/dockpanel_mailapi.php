<?php
/**
 * DockPanel Mail API — per-mailbox tokens for the DockPanel mail REST API.
 *
 * Adds a "Mail API" tab under Settings where a logged-in user can mint and
 * revoke API tokens for their own mailbox. Tokens are stored (hashed) in
 * Roundcube's own database — the same database the `dockpanel-mailapi` daemon
 * reads to authenticate `Authorization: Bearer <token>` requests.
 *
 * The daemon, not this plugin, performs the actual send: an offline REST caller
 * has no Roundcube session, and Roundcube only ever holds the mailbox password
 * inside that session, so a token-only request cannot reuse Roundcube's
 * authenticated submission. The daemon injects through the loopback smtpd
 * (already in Postfix `mynetworks`), which keeps DKIM signing intact, and files
 * a copy into the sender's Sent folder with `doveadm` so it shows up here.
 *
 * See panel/mailapi (Rust) for the API side.
 */
class dockpanel_mailapi extends rcube_plugin
{
    /** Only relevant on the Settings screens. */
    public $task = 'settings';

    /** @var rcmail */
    private $rc;
    private $table_ready = false;

    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->add_texts('localization/', true);

        $this->add_hook('settings_actions', [$this, 'settings_actions']);
        $this->register_action('plugin.dockpanel_mailapi', [$this, 'render_page']);
        $this->register_action('plugin.dockpanel_mailapi-save', [$this, 'handle_save']);

        // The daemon reads this table, so it must exist as soon as the plugin is
        // active — not only after someone opens the tab.
        $this->ensure_table();
    }

    /**
     * Add the "Mail API" entry to the Settings tab strip.
     */
    public function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.dockpanel_mailapi',
            'type'   => 'link',
            'label'  => 'mailapi_menu',
            'title'  => 'mailapi_menu',
            'domain' => 'dockpanel_mailapi',
        ];

        return $args;
    }

    /**
     * Create the token table on first use. Kept here (not in a migration) so the
     * plugin is self-contained: mounting it into a fresh Roundcube is enough.
     */
    private function ensure_table()
    {
        if ($this->table_ready || !$this->rc->db) {
            return;
        }
        $this->rc->db->query(
            "CREATE TABLE IF NOT EXISTS dockpanel_mailapi_tokens (
                token_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL,
                email        VARCHAR(255) NOT NULL,
                token_hash   VARCHAR(64) NOT NULL,
                token_prefix VARCHAR(12) NOT NULL,
                created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                revoked      INTEGER NOT NULL DEFAULT 0
            )"
        );
        $this->table_ready = true;
    }

    public function render_page()
    {
        $this->ensure_table();
        $this->register_handler('plugin.body', [$this, 'page_body']);
        $this->rc->output->set_pagetitle($this->gettext('mailapi_title'));
        $this->rc->output->send('plugin');
    }

    public function handle_save()
    {
        $this->ensure_table();

        $op = rcube_utils::get_input_value('_op', rcube_utils::INPUT_POST);

        if ($op === 'generate' && $this->rc->db) {
            $token = bin2hex(random_bytes(24));
            $this->rc->db->query(
                "INSERT INTO dockpanel_mailapi_tokens
                    (user_id, email, token_hash, token_prefix, created_at)
                 VALUES (?, ?, ?, ?, ?)",
                $this->rc->get_user_id(),
                $this->rc->get_user_name(),
                hash('sha256', $token),
                substr($token, 0, 8),
                date('Y-m-d H:i:s')
            );
            // Shown once on the next render, then dropped from the session.
            $_SESSION['dockpanel_mailapi_newtoken'] = $token;
            $this->rc->output->command('display_message', $this->gettext('tokencreated_msg'), 'confirmation');
        } elseif ($op === 'revoke' && $this->rc->db) {
            $id = (int) rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);
            $this->rc->db->query(
                "UPDATE dockpanel_mailapi_tokens SET revoked = 1
                 WHERE token_id = ? AND user_id = ?",
                $id,
                $this->rc->get_user_id()
            );
            $this->rc->output->command('display_message', $this->gettext('tokenrevoked_msg'), 'confirmation');
        }

        // Re-render in place (avoids a fragile cross-request redirect).
        $this->register_handler('plugin.body', [$this, 'page_body']);
        $this->rc->output->set_pagetitle($this->gettext('mailapi_title'));
        $this->rc->output->send('plugin');
    }

    public function page_body()
    {
        $base = rtrim((string) $this->rc->config->get('mailapi_url', ''), '/');
        if ($base === '') {
            $base = 'https://' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost');
        }

        $out = '';
        $out .= '<p class="mailapi-intro">' . rcube::Q($this->gettext('intro')) . '</p>';

        // A freshly minted token is the only time its value is visible.
        if (!empty($_SESSION['dockpanel_mailapi_newtoken'])) {
            $token = $_SESSION['dockpanel_mailapi_newtoken'];
            unset($_SESSION['dockpanel_mailapi_newtoken']);
            $out .= '<div class="mailapi-newtoken" style="border:1px solid #4f46e5;border-radius:8px;padding:12px;margin:12px 0;background:#eef2ff;">'
                . '<p style="margin:0 0 6px;font-weight:600;">' . rcube::Q($this->gettext('tokencreated')) . '</p>'
                . '<code style="display:block;word-break:break-all;user-select:all;">' . rcube::Q($token) . '</code>'
                . '</div>';
        }

        $out .= '<p><strong>' . rcube::Q($this->gettext('endpoint')) . '</strong> '
            . '<code>' . rcube::Q($base) . '/v1/send</code></p>';

        $example = "curl -X POST " . $base . "/v1/send \\\n"
            . "  -H \"Authorization: Bearer <TOKEN>\" \\\n"
            . "  -H \"Content-Type: application/json\" \\\n"
            . "  -d '{\"to\":\"someone@example.com\",\"subject\":\"Hello\",\"text\":\"Hi there\"}'";
        $out .= '<pre style="overflow:auto;background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;">'
            . rcube::Q($example) . '</pre>';

        $out .= $this->tokens_table();

        // Generate a new token.
        $save_url = $this->rc->url(['_task' => 'settings', '_action' => 'plugin.dockpanel_mailapi-save']);
        $token_field = new html_hiddenfield(['name' => '_token', 'value' => $this->rc->get_request_token()]);
        $op_field = new html_hiddenfield(['name' => '_op', 'value' => 'generate']);
        $out .= '<p style="margin-top:16px;"><form method="post" action="' . rcube::Q($save_url) . '">'
            . $token_field->show() . $op_field->show()
            . '<button type="submit" class="button mainaction">' . rcube::Q($this->gettext('generate')) . '</button>'
            . '</form></p>';

        return $out;
    }

    private function tokens_table()
    {
        $rows = [];
        if ($this->rc->db) {
            $res = $this->rc->db->query(
                "SELECT token_id, token_prefix, created_at, last_used_at
                 FROM dockpanel_mailapi_tokens
                 WHERE user_id = ? AND revoked = 0
                 ORDER BY token_id DESC",
                $this->rc->get_user_id()
            );
            if ($res) {
                $rows = $res->fetchAll();
            }
        }

        if (empty($rows)) {
            return '<p class="mailapi-none">' . rcube::Q($this->gettext('notokens')) . '</p>';
        }

        $save_url = $this->rc->url(['_task' => 'settings', '_action' => 'plugin.dockpanel_mailapi-save']);
        $token_field = new html_hiddenfield(['name' => '_token', 'value' => $this->rc->get_request_token()]);
        $revoke_field = new html_hiddenfield(['name' => '_op', 'value' => 'revoke']);

        $h = '<table class="records-table" style="width:100%;margin-top:12px;"><thead><tr>'
            . '<th>' . rcube::Q($this->gettext('col_prefix')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_created')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_lastused')) . '</th>'
            . '<th></th></tr></thead><tbody>';

        foreach ($rows as $r) {
            $id_field = new html_hiddenfield(['name' => '_id', 'value' => (string) $r['token_id']]);
            $h .= '<tr>'
                . '<td><code>' . rcube::Q($r['token_prefix']) . '…</code></td>'
                . '<td>' . rcube::Q((string) $r['created_at']) . '</td>'
                . '<td>' . rcube::Q($r['last_used_at'] ? (string) $r['last_used_at'] : $this->gettext('never')) . '</td>'
                . '<td><form method="post" action="' . rcube::Q($save_url) . '">'
                . $token_field->show() . $revoke_field->show() . $id_field->show()
                . '<button type="submit" class="button">' . rcube::Q($this->gettext('revoke')) . '</button>'
                . '</form></td></tr>';
        }

        return $h . '</tbody></table>';
    }
}
