<?php
/**
 * DockPanel Mail API — a read-only view of a mailbox's REST API tokens.
 *
 * Adds a "Mail API" tab under Settings. It no longer creates or stores tokens:
 * the panel owns them now (panel/backend/src/routes/mail_api.rs), along with the
 * roles and permissions that decide what a token may do, and the
 * `dockpanel-mailapi` daemon authenticates against the panel's database rather
 * than this container's SQLite.
 *
 * What this tab does is LIST — the tokens of the address the signed-in user
 * holds, so they can see what exists and when it was last used. To do that it
 * calls the panel with a key the panel minted for this webmail install and
 * scoped to exactly that read (read `mail_api_webmail_clients`). It cannot mint,
 * revoke, or read a secret; minting and revoking happen in the panel under
 * Mail -> Mail API, which is where the button below points.
 *
 * The old plugin wrote a `dockpanel_mailapi_tokens` table into Roundcube's
 * SQLite. That table is left untouched and unread here: the daemon still honours
 * tokens found in it, granting them `me` and nothing more, so existing
 * integrations keep working while a mailbox moves to panel-minted tokens.
 *
 * Layout note: the page is a table with two lines of context above it. The curl
 * example is folded into a <details>, because the list is what a mailbox owner
 * comes here for; the example is what they open once. Styles are structural and
 * colourless (borders and spacing in rgba greys) so the page reads correctly in
 * both of Roundcube's skins.
 *
 * See panel/mailapi (Rust) for the API side and panel/backend for the tokens.
 */
class dockpanel_mailapi extends rcube_plugin
{
    /** Only relevant on the Settings screens. */
    public $task = 'settings';

    /** @var rcmail */
    private $rc;

    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->add_texts('localization/', true);

        $this->add_hook('settings_actions', [$this, 'settings_actions']);
        $this->register_action('plugin.dockpanel_mailapi', [$this, 'render_page']);
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

    public function render_page()
    {
        $this->register_handler('plugin.body', [$this, 'page_body']);
        $this->rc->output->set_pagetitle($this->gettext('mailapi_title'));
        $this->rc->output->send('plugin');
    }

    /** The panel's base URL, as written into this container's config. */
    private function panel_url()
    {
        return rtrim((string) $this->rc->config->get('mailapi_panel_url', ''), '/');
    }

    /**
     * Ask the panel for this mailbox's tokens.
     *
     * Returns the token list, or `null` when the panel could not be reached or
     * refused us — the two are reported the same way on purpose: to a signed-in
     * user they mean the same thing ("the list is not available right now"), and
     * the panel's own logs carry the reason.
     */
    private function fetch_tokens($email)
    {
        $base = $this->panel_url();
        $key = (string) $this->rc->config->get('mailapi_client_key', '');
        if ($base === '' || $key === '') {
            return null;
        }

        $url = $base . '/api/mail/webmail/tokens?email=' . rawurlencode($email);

        if (!function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT        => 6,
            // A plain UA: the panel's public vhost sits behind a WAF that
            // refuses the default cURL agent, and a 403 here would look like the
            // panel being down.
            CURLOPT_USERAGENT      => 'DockPanel-Webmail/1.0',
            CURLOPT_HTTPHEADER     => [
                'X-Mail-Webmail-Key: ' . $key,
                'Accept: application/json',
            ],
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($body === false || $status < 200 || $status >= 300) {
            return null;
        }

        $data = json_decode((string) $body, true);
        return isset($data['tokens']) && is_array($data['tokens']) ? $data['tokens'] : [];
    }

    public function page_body()
    {
        $base = rtrim((string) $this->rc->config->get('mailapi_url', ''), '/');
        if ($base === '') {
            $base = 'https://' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost');
        }

        $out = '';
        $out .= '<style>'
            . '.mailapi-intro{margin:0 0 6px}'
            . '.mailapi-endpoint{margin:0 0 8px;font-size:12px;opacity:.75}'
            . '.mailapi-example{margin:0 0 14px}'
            . '.mailapi-example summary{cursor:pointer;font-size:12px;opacity:.75}'
            . '.mailapi-example summary:hover{opacity:1}'
            . '.mailapi-example pre{overflow:auto;padding:10px;margin:8px 0 0;border-radius:6px;'
            . 'background:rgba(127,127,127,.14);color:inherit}'
            . '.mailapi-managed{border:1px solid rgba(127,127,127,.35);border-radius:6px;'
            . 'padding:8px 10px;margin:0 0 14px;font-size:12px}'
            . '.mailapi-managed p{margin:0}'
            . '.mailapi-list-title{margin:0 0 4px}'
            . '.mailapi-table{width:100%}'
            . '.mailapi-table td,.mailapi-table th{vertical-align:top}'
            . '.mailapi-nowrap{white-space:nowrap}'
            . '.mailapi-legend{margin:8px 0 0;font-size:11px;opacity:.75}'
            . '</style>';

        $out .= '<p class="mailapi-intro">' . rcube::Q($this->gettext('intro')) . '</p>';

        $out .= '<p class="mailapi-endpoint">' . rcube::Q($this->gettext('endpoint')) . ' '
            . '<code>' . rcube::Q($base) . '/v1/send</code></p>';

        $example = "curl -X POST " . $base . "/v1/send \\\n"
            . "  -H \"Authorization: Bearer <TOKEN>\" \\\n"
            . "  -H \"Content-Type: application/json\" \\\n"
            . "  -d '{\"to\":\"someone@example.com\",\"subject\":\"Hello\",\"text\":\"Hi there\"}'";
        $out .= '<details class="mailapi-example"><summary>' . rcube::Q($this->gettext('example_title')) . '</summary>'
            . '<pre>' . rcube::Q($example) . '</pre></details>';

        $out .= $this->tokens_section($this->rc->get_user_name());

        return $out;
    }

    /**
     * The token list, plus the one sentence that matters: it is managed, and
     * minted, in the panel.
     */
    private function tokens_section($email)
    {
        $panel = $this->panel_url();
        $link = $panel !== ''
            ? ' <a href="' . rcube::Q($panel . '/mail') . '" target="_blank" rel="noopener">'
                . rcube::Q($this->gettext('open_panel')) . '</a>'
            : '';

        $out = '<div class="mailapi-managed">'
            . '<p><strong>' . rcube::Q($this->gettext('managed_title')) . '</strong> '
            . rcube::Q($this->gettext('managed_body')) . $link . '</p>'
            . '</div>';

        $tokens = $this->fetch_tokens($email);
        if ($tokens === null) {
            $out .= '<p class="mailapi-list-title"><strong>' . rcube::Q($this->gettext('list_title')) . '</strong></p>'
                . '<p class="mailapi-unavailable">' . rcube::Q($this->gettext('unavailable')) . '</p>';
            return $out;
        }
        if (empty($tokens)) {
            $out .= '<p class="mailapi-list-title"><strong>' . rcube::Q($this->gettext('list_title')) . '</strong></p>'
                . '<p class="mailapi-none">' . rcube::Q($this->gettext('notokens')) . '</p>';
            return $out;
        }

        $out .= '<p class="mailapi-list-title"><strong>' . rcube::Q($this->gettext('list_title'))
            . '</strong> <span style="opacity:.6">(' . count($tokens) . ')</span></p>';

        $h = '<table class="records-table mailapi-table"><thead><tr>'
            . '<th>' . rcube::Q($this->gettext('col_prefix')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_name')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_permissions')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_expires')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_created')) . '</th>'
            . '<th>' . rcube::Q($this->gettext('col_lastused')) . '</th>'
            . '</tr></thead><tbody>';

        foreach ($tokens as $r) {
            $perms = isset($r['permissions']) && is_array($r['permissions'])
                ? implode(', ', array_map('strval', $r['permissions']))
                : '';
            $h .= '<tr>'
                . '<td class="mailapi-nowrap"><code>' . rcube::Q((string) ($r['token_prefix'] ?? '')) . '…</code></td>'
                . '<td>' . rcube::Q((string) ($r['name'] ?? '')) . '</td>'
                . '<td>' . rcube::Q($perms) . '</td>'
                . '<td class="mailapi-nowrap">' . $this->expiry_cell($r['expires_at'] ?? null) . '</td>'
                . '<td class="mailapi-nowrap">' . rcube::Q($this->short_date($r['created_at'] ?? null)) . '</td>'
                . '<td class="mailapi-nowrap">'
                . rcube::Q(!empty($r['last_used_at']) ? $this->short_date($r['last_used_at']) : $this->gettext('never'))
                . '</td>'
                . '</tr>';
        }

        $out .= $h . '</tbody></table>';
        $out .= '<p class="mailapi-legend">' . rcube::Q($this->gettext('perms_legend')) . '</p>';

        return $out;
    }

    /**
     * The expiry cell: "never", a date, or "expired <date>" — so a token that
     * has silently stopped working says so on the page rather than looking valid
     * until a send fails. Marked up rather than coloured, so it stays legible in
     * both skins.
     */
    private function expiry_cell($expires_at)
    {
        $value = trim((string) $expires_at);
        if ($value === '') {
            return rcube::Q($this->gettext('never'));
        }
        $ts = strtotime($value);
        if ($ts !== false && $ts < time()) {
            return '<strong>' . rcube::Q($this->gettext('expired')) . '</strong> '
                . rcube::Q(date('Y-m-d', $ts));
        }
        return rcube::Q($ts !== false ? date('Y-m-d', $ts) : $value);
    }

    /**
     * "2026-10-18 07:12" — a compact, sortable date in place of the raw ISO
     * timestamp the panel returns. Unknown values are passed through unchanged.
     */
    private function short_date($value)
    {
        $value = trim((string) $value);
        if ($value === '') {
            return '';
        }
        $ts = strtotime($value);
        return $ts !== false ? date('Y-m-d H:i', $ts) : $value;
    }
}
