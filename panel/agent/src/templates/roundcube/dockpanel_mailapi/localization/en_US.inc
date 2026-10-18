<?php
$labels = [];

$labels['mailapi_menu']        = 'Mail API';
$labels['mailapi_title']       = 'Mail API Tokens';
$labels['intro']               = 'Use these tokens to send email from applications through the server\'s mail API. Each token sends as your own address only — every message is DKIM-signed and filed in your Sent folder — and each carries its own permissions. Treat a token like a password.';
$labels['endpoint']            = 'API endpoint:';
$labels['example_title']       = 'Show an example request';
$labels['managed_title']       = 'Managed in the DockPanel panel.';
$labels['managed_body']        = 'Creating, revoking and scoping tokens happens under Mail &rarr; Mail API, so it can require a permission check and leave an audit trail. This tab only lists what exists.';
$labels['open_panel']          = 'Open the panel';
$labels['list_title']          = 'Your tokens';
$labels['unavailable']         = 'The token list could not be loaded from the panel right now. It will work again once the panel is reachable; nothing has changed about your existing tokens.';
$labels['notokens']            = 'You have no API tokens yet. Create one in the panel under Mail &rarr; Mail API.';
$labels['col_prefix']          = 'Token';
$labels['col_name']            = 'Name';
$labels['col_permissions']     = 'Permissions';
$labels['col_expires']         = 'Expires';
$labels['col_created']         = 'Created';
$labels['col_lastused']        = 'Last used';
$labels['perms_legend']        = 'send — mails out as your address; read — reads your messages, folders and settings; write — changes them; domain — administers the whole server.';
$labels['never']               = 'never';
$labels['expired']             = 'expired';
