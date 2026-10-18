<?php
$labels = [];

$labels['mailapi_menu']        = 'Mail API';
$labels['mailapi_title']       = 'Mail API Tokens';
$labels['intro']               = 'Use these tokens to send email from applications through the server\'s mail API. Each token sends as your own address only, every message is signed with DKIM and filed in your Sent folder, and each token carries its own permissions. Treat a token like a password.';
$labels['endpoint']            = 'API endpoint:';
$labels['managed_title']       = 'Manage tokens in the DockPanel panel';
$labels['managed_body']        = 'Creating, revoking and scoping tokens happens in the panel, under Mail &rarr; Mail API, so it can require a permission check and leave an audit trail. This tab only lists what exists.';
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
$labels['revoke']              = 'Revoke';
$labels['never']               = 'never';
$labels['expired']             = 'expired';
