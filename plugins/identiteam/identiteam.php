<?php
/*
 * Identiteam: Create users' identities and signature by querying an LDAP server.
 * Author: André Rodier <andre.rodier@gmail.com>
 * Licence: GPLv3. (See copying)
 */
class identiteam extends rcube_plugin
{
    public $task = 'login|settings';

    private $config;
    /**
     * @var rcmail
     */
    private $app;

    // mail parameters
    private $mail;

    // LDAP parameters
    private $ldap;
    private $server;
    private $port;
    private $filter;
    private $domain;
    private $fields;
    private $conn;
    private $use_at_creation;
    private $check_at_creation;
    private $check_at_update;

    // Internal flags
    private $initialised;

    function init()
    {
        try {
            write_log('identiteam', 'Initialising');

            // Load default config, and merge with users' settings
            $this->load_config('config-default.inc.php');
            $this->load_config('config.inc.php');

            $this->app = rcmail::get_instance();
            $this->config = $this->app->config->get('identiteam');

            // Load LDAP & mail config at once
            $this->ldap = $this->config['ldap'];
            $this->mail = $this->config['mail'];

            $this->server = $this->ldap['server'];
            $this->port = $this->ldap['port'];
            $this->filter = $this->ldap['filter'];
            $this->domain = $this->ldap['domain'];

            $this->use_at_creation = $this->ldap['use_at_creation'];
            $this->check_at_creation = $this->ldap['check_at_creation'];
            $this->check_at_update = $this->ldap['check_at_update'];

            // Get these fields
            $this->fields = explode(',', $this->ldap['fields']);
            array_push($this->fields, $this->ldap['extraEmailField']);

            $this->add_hook('user2email', array($this, 'user2email'));
            if ($this->use_at_creation) {
                $this->add_hook('identity_form', array($this, 'identity_form'));
            }
            if ($this->check_at_creation) {
                $this->add_hook('identity_create', array($this, 'identity_create_or_update'));
            }
            if ($this->check_at_update) {
                $this->add_hook('identity_update', array($this, 'identity_create_or_update'));
            }

            $this->initialised = true;

        } catch (Exception $exc) {
            write_log('identiteam', 'Fail to initialise: ' . $exc->getMessage());
        }

        if ($this->initialised) {
            write_log('identiteam', 'Initialised');
        }
    }

    public function identity_create_or_update($arguments) {
        try {
            if (strchr($arguments['record']['email'], '@')) {
                $arguments['abort'] = true;
                $domain_to_check = array_pop(explode('@', $arguments['record']['email']));
                $domain = $this->getDomainFromSession();
                if ($domain === false) {
                    $info = $this->getLdapData($arguments['record']['email']);
                    if ($info['count'] == 1) {
                        $domain = (array_pop(explode('@', $info[0]["mail"][0])));
                        $this->setDomainToSession($domain);
                    }
                }
                if ($domain_to_check && $domain && strtolower($domain_to_check)===strtolower($domain)) {
                    $arguments['abort'] = false;
                }
            }
        } catch (Exception $exc) {
            write_log('identiteam', 'Fail to check email: ' . $exc->getMessage());
        }
        return($arguments);
    }

    public function identity_form($arguments) {
        try {
            if (!$arguments['record']['email']) {
                $domain = $this->getDomainFromSession();
                if ($domain === false) {
                    $info = $this->getLdapData($arguments['record']['email']);
                    if ($info['count'] == 1) {
                        $domain = (array_pop(explode('@', $info[0]["mail"][0])));
                        $this->setDomainToSession($domain);
                    }
                }
                $login = $this->app->get_user_name();
                $arguments['record']['email'] = "$login@$domain";
            }
        } catch (Exception $exc) {
            write_log('identiteam', 'Fail to prepare form: ' . $exc->getMessage());
        }

        return($arguments);
    }

    /**
     * user2email
     *
     * See http://trac.roundcube.net/wiki/Plugin_Hooks
     * Return values:
     * email: E-mail address (or array of arrays with keys: email, name, organization, reply-to, bcc, signature, html_signature)
     */
    function user2email($args)
    {
        $login = $args['user']; // User login
        $first = $args['first']; // True if one entry is expected
        $extended = $args['extended']; // True if array result (email and identity data) is expected
        $email = $args['email'];

        // ensure we return valid information
        $args['extended'] = true;
        $args['first'] = false;
        $args['abort'] = false;

        try {

            if ($info = $this->getLdapData($login)) {

                if ($info['count'] == 1) {
                    $log = sprintf("Found the user '%s' in the database", $login);
                    write_log('identiteam', $log);

                    $userInfo = $info[0];
                    $identities = array();
                    $emails = array($userInfo["mail"][0]);

                    if (!$this->getDomainFromSession()) {
                        $this->setDomainToSession(array_pop(explode('@', $userInfo["mail"][0])));
                    }

                    $extraEmailField = $this->ldap['extraEmailField'];
                    $extraEmails = $userInfo[$extraEmailField];

                    if ($extraEmails['count'] > 0) {
                        $count = $extraEmails['count'];

                        for ($e = 0; $e < $count; $e++) {
                            array_push($emails, $extraEmails[$e]);
                        }
                    }

                    foreach ($emails as $email) {
                        $dict = array();
                        $keys = array_keys($userInfo);
                        foreach ($keys as $key) {
                            $dict["[$key]"] = $userInfo[$key][0];
                        }
                        $dict['[mail]'] = $email;

                        $log = sprintf("Found the email '%s'", $email);
                        write_log('identiteam', $log);

                        // prepare the arrays to replace into the signature template
                        $keys = array_keys($dict);
                        $vals = array_values($dict);

                        $tmplConfig = $this->config['templates'];
                        $baseDir = $tmplConfig['baseDir'];
                        $extension = $tmplConfig['extension'];
                        $folderName = $tmplConfig['folderName'];
                        $fileName = $tmplConfig['fileName'];
                        $formatString = $tmplConfig['formatString'];

                        if ($folderName == '%d' || $fileName == '%u') {
                            list($user, $domain) = explode('@', $email);

                            if ($folderName == '%d') {
                                $folderName = $domain;
                            }
                            if ($fileName == '%u') {
                                $fileName = $user;
                            }
                        }

                        $signPath = sprintf($formatString, $baseDir, $folderName, $fileName, $extension);

                        if (!file_exists($signPath)) {
                            $log = sprintf(
                                "Signature template not found: (path=%s). Trying default in custom folder",
                                $signPath
                            );
                            write_log('identiteam', $log);
                            $signPath = sprintf("%s/default/default.%s", $baseDir, $extension);
                        }
                        if (!file_exists($signPath)) {
                            $log = sprintf("Signature template not found: (path=%s). Using default one", $signPath);
                            write_log('identiteam', $log);
                            $signPath = "plugins/identiteam/templates/default/default.tmpl";
                        }

                        // Create signature
                        if (file_exists($signPath)) {
                            $log = sprintf("Creating signature with template: (path=%s).", $signPath);
                            write_log('identiteam', $log);

                            $sign = file_get_contents($signPath);
                            $sign = str_replace($keys, $vals, $sign);

                            // remove empty fields from the signature
                            $repl = $tmplConfig['emptyValues'];
                            $sign = preg_replace('/\[[a-zA-Z]+\]/', $repl, $sign);

                            // If the signature start with an HTNL tag,
                            // it is automatically considered as an HTML signature.
                            $isHtml = 0;
                            if (preg_match('/^\s*<[a-zA-Z]+/', $sign)) {
                                $isHtml = 1;
                            }

                            $organisation = $userInfo['o'][0];
                            $name = $userInfo['sn'][0]?$userInfo['sn'][0]:$userInfo['cn'][0];

                            if (!$organisation) {
                                $organisation = '';
                            }
                            if (!$name) {
                                $name = '';
                            }

                            $identities[] = array(
                                'email' => $email,
                                'name' => $name,
                                'organization' => $organisation,
                                'reply-to' => '',
                                'signature' => $sign,
                                'html_signature' => $isHtml
                            );
                        } else {
                            $log = sprintf("Warning: signature template not found: (path=%s)", $signPath);
                            write_log('identiteam', $log);
                        }
                    }

                    $args['email'] = $identities;
                } else {
                    $log = sprintf("User '%s' not found (pass 2).", $login);
                    write_log('identiteam', $log);
                }

            }

        } catch (Exception $exc) {
            write_log('identiteam', 'Fail to create signature: ' . $exc->getMessage());
        }

        return $args;
    }

    private function getLdapData($login) {
        // load ldap & mail confg
        $ldap = $this->ldap;
        $mail = $this->mail;

        // if set to true, the domain name is removed before the lookup
        $filter_remove_domain = $this->config['ldap']['filter_remove_domain'];

        if ($filter_remove_domain) {
            $login = array_shift(explode('@', $login));
        } else {
            // check if we need to add a domain if not specified in the login name
            if (!strstr($login, '@') && $mail['domain']) {
                $domain = $mail['domain'];
                $login = "$login@$domain";
            }
        }

        // Check if dovecot master user is used. Use the same configuration name than
        // dovecot_impersonate plugin for roundcube
        $separator = $this->config['mail']['dovecot_impersonate_seperator'];

        if (strpos($login, $separator) !== false) {
            $log = sprintf("Removed dovecot impersonate separator (%s) in the login name", $separator);
            write_log('identiteam', $log);

            $login = array_shift(explode($separator, $login));
        }

        $filter = sprintf($ldap['filter'], $login);

        $this->conn = ldap_connect($this->server, $this->port);

        if (is_resource($this->conn)) {
            ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);

            $bound = ldap_bind($this->conn);

            if ($bound) {
                write_log('identiteam', 'Ldap connected');
            } else {
                $log = sprintf(
                    "Bind to server '%s' failed. Con: (%s), Error: (%s)",
                    $this->server,
                    $this->conn,
                    ldap_errno($this->conn)
                );
                write_log('identiteam', $log);
                return false;
            }
        } else {
            $log = sprintf("Connection to the server failed: (Error=%s)", ldap_errno($this->conn));
            write_log('identiteam', $log);
            return false;
        }

        $result = ldap_search($this->conn, $this->domain, $filter, $this->fields);

        if ($result) {
            $data = ldap_get_entries($this->conn, $result);
        } else {
            $data = false;
            $log = sprintf("User '%s' not found (pass 1). Filter: %s", $login, $filter);
            write_log('identiteam', $log);
        }
        // We may close the connection before,
        // unless closing connection freed ressources
        // we use...
        ldap_close($this->conn);

        return $data;
    }

    private function setDomainToSession($domain) {
        $this->app->session->append('plugins.identiteam', 'ldap_email_domain', $domain);
    }

    private function getDomainFromSession() {
        if (array_key_exists('plugins', $_SESSION)
            && is_array($_SESSION['plugins'])
            && array_key_exists('identiteam', $_SESSION['plugins'])
            && is_array($_SESSION['plugins']['identiteam'])
            && array_key_exists('ldap_email_domain', $_SESSION['plugins']['identiteam'])
        ) {
            return $_SESSION['plugins']['identiteam']['ldap_email_domain'];
        }
        return false;
    }


}

?>
