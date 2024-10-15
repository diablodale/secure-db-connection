<?php
/**
 * Plugin name: Secure DB Connection
 * Plugin URI: http://wordpress.org/plugins/secure-db-connection/
 * Description: Sets SSL keys and certs for encrypted database connections
 * Author: Xiao Yu, Dale Phurrough
 * Author URI: http://xyu.io/
 * Version: 1.1.7
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class WP_SecureDBConnection_DB extends wpdb {

	/**
	 * Connect to and select database.
	 *
	 * If $allow_bail is false, the lack of database connection will need
	 * to be handled manually.
	 *
	 * @since 3.0.0
	 * @since 3.9.0 $allow_bail parameter added.
	 *
	 * @param bool $allow_bail Optional. Allows the function to bail. Default true.
	 * @return bool True with a successful connection, false on failure.
	 */
	public function db_connect( $allow_bail = true ) {
		$this->is_mysql = true;

		$client_flags = defined( 'MYSQL_CLIENT_FLAGS' ) ? MYSQL_CLIENT_FLAGS : 0;

		/*
		 * Set the MySQLi error reporting off because WordPress handles its own.
		 * This is due to the default value change from `MYSQLI_REPORT_OFF`
		 * to `MYSQLI_REPORT_ERROR|MYSQLI_REPORT_STRICT` in PHP 8.1.
		 */
		mysqli_report( MYSQLI_REPORT_OFF );

		$this->dbh = mysqli_init();

		$host    = $this->dbhost;
		$port    = null;
		$socket  = null;
		$is_ipv6 = false;

		$host_data = $this->parse_db_host( $this->dbhost );
		if ( $host_data ) {
			list( $host, $port, $socket, $is_ipv6 ) = $host_data;
		}

		/*
		 * If using the `mysqlnd` library, the IPv6 address needs to be enclosed
		 * in square brackets, whereas it doesn't while using the `libmysqlclient` library.
		 * @see https://bugs.php.net/bug.php?id=67563
		 */
		if ( $is_ipv6 && extension_loaded( 'mysqlnd' ) ) {
			$host = "[$host]";
		}

        // Set SSL certs if we want to use secure DB connections
        $ssl_opts = array(
            'KEY'     => ( defined( 'MYSQL_SSL_KEY'     ) && is_file( MYSQL_SSL_KEY     ) ) ? MYSQL_SSL_KEY     : null,
            'CERT'    => ( defined( 'MYSQL_SSL_CERT'    ) && is_file( MYSQL_SSL_CERT    ) ) ? MYSQL_SSL_CERT    : null,
            'CA'      => ( defined( 'MYSQL_SSL_CA'      ) && is_file( MYSQL_SSL_CA      ) ) ? MYSQL_SSL_CA      : null,
            'CA_PATH' => ( defined( 'MYSQL_SSL_CA_PATH' ) && is_dir ( MYSQL_SSL_CA_PATH ) ) ? MYSQL_SSL_CA_PATH : null,
            'CIPHER'  => ( defined( 'MYSQL_SSL_CIPHER'  ) && false != MYSQL_SSL_CIPHER    ) ? MYSQL_SSL_CIPHER  : null,
        );
        $ssl_opts_set = false;
        foreach ( $ssl_opts as $ssl_opt_val ) {
            if ( !is_null( $ssl_opt_val ) ) {
                $ssl_opts_set = true;
                break;
            }
        }
        if ( MYSQLI_CLIENT_SSL !== ( $client_flags & MYSQLI_CLIENT_SSL ) ) {
            $ssl_opts_set = false;
        }
        if ( $ssl_opts_set ) {
            mysqli_ssl_set(
                $this->dbh,
                $ssl_opts[ 'KEY'     ],
                $ssl_opts[ 'CERT'    ],
                $ssl_opts[ 'CA'      ],
                $ssl_opts[ 'CA_PATH' ],
                $ssl_opts[ 'CIPHER'  ]
            );
        }

        if ( WP_DEBUG ) {
			mysqli_real_connect( $this->dbh, $host, $this->dbuser, $this->dbpassword, null, $port, $socket, $client_flags );
		} else {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			@mysqli_real_connect( $this->dbh, $host, $this->dbuser, $this->dbpassword, null, $port, $socket, $client_flags );
		}

		if ( $this->dbh->connect_errno ) {
			$this->dbh = null;
		}

		if ( ! $this->dbh && $allow_bail ) {
			wp_load_translations_early();

			// Load custom DB error template, if present.
			if ( file_exists( WP_CONTENT_DIR . '/db-error.php' ) ) {
				require_once WP_CONTENT_DIR . '/db-error.php';
				die();
			}

			$message = '<h1>' . __( 'Error establishing a database connection' ) . "</h1>\n";

			$message .= '<p>' . sprintf(
				/* translators: 1: wp-config.php, 2: Database host. */
				__( 'This either means that the username and password information in your %1$s file is incorrect or that contact with the database server at %2$s could not be established. This could mean your host&#8217;s database server is down.' ),
				'<code>wp-config.php</code>',
				'<code>' . htmlspecialchars( $this->dbhost, ENT_QUOTES ) . '</code>'
			) . "</p>\n";

			$message .= "<ul>\n";
			$message .= '<li>' . __( 'Are you sure you have the correct username and password?' ) . "</li>\n";
			$message .= '<li>' . __( 'Are you sure you have typed the correct hostname?' ) . "</li>\n";
			$message .= '<li>' . __( 'Are you sure the database server is running?' ) . "</li>\n";
			$message .= "</ul>\n";

			$message .= '<p>' . sprintf(
				/* translators: %s: Support forums URL. */
				__( 'If you are unsure what these terms mean you should probably contact your host. If you still need help you can always visit the <a href="%s">WordPress support forums</a>.' ),
				__( 'https://wordpress.org/support/forums/' )
			) . "</p>\n";

			$this->bail( $message, 'db_connect_fail' );

			return false;
		} elseif ( $this->dbh ) {
			if ( ! $this->has_connected ) {
				$this->init_charset();
			}

			$this->has_connected = true;

			$this->set_charset( $this->dbh );

			$this->ready = true;
			$this->set_sql_mode();
			$this->select( $this->dbname, $this->dbh );

			return true;
		}

		return false;
	}

}

$wpdb = new WP_SecureDBConnection_DB( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
