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
        $out .= '<p class="mailapi-intro">' . rcube::Q($this->gettext('intro')) . '</p>';

        $out .= '<p><strong>' . rcube::Q($this->gettext('endpoint')) . '</strong> '
            . '<code>' . rcube::Q($base) . '/v1/send</code></p>';

        $example = "curl -X POST " . $base . "/v1/send \\\n"
            . "  -H \"Authorization: Bearer <TOKEN>\" \\\n"
            . "  -H \"Content-Type: application/json\" \\\n"
            . "  -d '{\"to\":\"someone@example.com\",\"subject\":\"Hello\",\"text\":\"Hi there\"}'";
        $out .= '<pre style="overflow:auto;background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;">'
            . rcube::Q($example) . '</pre>';

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

        $out = '<div class="mailapi-managed" style="border:1px solid #cbd5e1;border-radius:8px;padding:12px;margin:16px 0;background:#f8fafc;">'
            . '<p style="margin:0 0 4px;font-weight:600;">' . rcube::Q($this->gettext('managed_title')) . '</p>'
            . '<p style="margin:0;">' . rcube::Q($this->gettext('managed_body')) . $link . '</p>'
            . '</div>';

        $out .= '<h3 style="margin-bottom:4px;">' . rcube::Q($this->gettext('list_title')) . '</h3>';

        $tokens = $this->fetch_tokens($email);
        if ($tokens === null) {
            $out .= '<p class="mailapi-unavailable">' . rcube::Q($this->gettext('unavailable')) . '</p>';
            return $out;
        }
        if (empty($tokens)) {
            $out .= '<p class="mailapi-none">' . rcube::Q($this->gettext('notokens')) . '</p>';
            return $out;
        }

        $h = '<table class="records-table" style="width:100%;margin-top:12px;"><thead><tr>'
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
                . '<td><code>' . rcube::Q((string) ($r['token_prefix'] ?? '')) . '…</code></td>'
                . '<td>' . rcube::Q((string) ($r['name'] ?? '')) . '</td>'
                . '<td>' . rcube::Q($perms) . '</td>'
                . '<td>' . rcube::Q($this->expiry_label($r['expires_at'] ?? null)) . '</td>'
                . '<td>' . rcube::Q((string) ($r['created_at'] ?? '')) . '</td>'
                . '<td>' . rcube::Q(!empty($r['last_used_at']) ? (string) $r['last_used_at'] : $this->gettext('never')) . '</td>'
                . '</tr>';
        }

        return $out . $h . '</tbody></table>';
    }

    /**
     * "never", an ISO date, or "expired <date>" once that date is behind us — so
     * a token that has silently stopped working says so on the page rather than
     * looking valid until a send fails.
     */
    private function expiry_label($expires_at)
    {
        $value = trim((string) $expires_at);
        if ($value === '') {
            return $this->gettext('never');
        }
        $ts = strtotime($value);
        if ($ts !== false && $ts < time()) {
            return $this->gettext('expired') . ' ' . $value;
        }
        return $value;
    }
}
