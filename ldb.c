#include <sqlite3.h>
#include <stdio.h>

static sqlite3	*ldb;

static sqlite3_stmt *client_create_stmt;
static char *client_create_sql = "INSERT INTO client (email, password, apikey) "
					"VALUES (LOWER(?), ?, ?);";

static sqlite3_stmt *client_activate_stmt;
static char *client_activate_sql = "UPDATE client SET status = 1 "
					"WHERE email = LOWER(?) AND apikey = ?;";

static sqlite3_stmt *client_apikey_set_stmt;
static char *client_apikey_set_sql = "UPDATE client SET apikey = ? "
					"WHERE email = LOWER(?) "
					"AND password = ? "
					"AND status = 1;";

static sqlite3_stmt *client_apikey_reset_stmt;
static char *client_apikey_reset_sql = "UPDATE client SET apikey = ? "
					"WHERE email = LOWER(?) "
					"AND apikey = ? "
					"AND status = 1;";

static sqlite3_stmt *client_recover_stmt;
static char *client_recover_sql = "UPDATE client SET recover_key = ?, recover_date = CURRENT_TIMESTAMP "
					"WHERE email = LOWER(?) "
					"AND (recover_date is NULL OR recover_date <= datetime('now', '-1 hours')) "
					"AND status = 1;";

static sqlite3_stmt *client_password_reset_stmt;
static char *client_password_reset_sql = "UPDATE client SET password = ?, recover_date = NULL, recover_key = NULL "
					"WHERE email = LOWER(?) "
					"AND recover_key = ? "
					"AND recover_date >= datetime('now', '-24 hours') "
					"AND status = 1;";

static sqlite3_stmt *network_create_stmt;
static char *network_create_sql = "INSERT INTO network (email, uid, description, subnet, netmask, "
					"embassy_certificate, embassy_privatekey, "
					"passport_certificate, passport_privatekey) "
					"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

// FIXME we need uid for this query
static sqlite3_stmt *network_get_stmt;
static char *network_get_sql = "SELECT uid, subnet, netmask FROM network "
				"WHERE email = ? "
				"AND description = ?;";

static sqlite3_stmt *network_list_stmt;
static char *network_list_sql = "SELECT uid, description FROM network,client "
				"WHERE network.email = client.email "
				"AND client.email = LOWER(?) "
				"AND client.apikey = ?;";

static sqlite3_stmt *network_embassy_get_stmt;
static char *network_embassy_get_sql = "SELECT embassy_certificate, embassy_privatekey, embassy_serial "
					"FROM network "
					"WHERE uid = ?;";


// FIXME create foreign key from network + ON DELETE CASCADE and ON UPDATE CASCADE

int
ldb_client_create(const char *email, const char *password, const char *apikey)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(client_create_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_create_stmt, 1, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_create_stmt, 2, password, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_create_stmt, 3, apikey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(client_create_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_client_activate(const char *email, const char *apikey)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(client_activate_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_activate_stmt, 1, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_activate_stmt, 2, apikey, -2, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(client_activate_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	if (sqlite3_changes(ldb) != 1) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_client_apikey_set(const char *email, const char *password, const char *apikey)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(client_apikey_set_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_apikey_set_stmt, 1, apikey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_apikey_set_stmt, 2, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_apikey_set_stmt, 3, password, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(client_apikey_set_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	if (sqlite3_changes(ldb) != 1) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_client_apikey_reset(const char *email, const char *apikey, const char *new_apikey)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(client_apikey_reset_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_apikey_reset_stmt, 1, new_apikey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_apikey_reset_stmt, 2, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_apikey_reset_stmt, 3, apikey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(client_apikey_reset_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	if (sqlite3_changes(ldb) != 1) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_client_recover(const char *email, const char *recover_key)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(client_recover_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_recover_stmt, 1, recover_key, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_recover_stmt, 2, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(client_recover_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	if (sqlite3_changes(ldb) != 1) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_client_password_reset(const char *email, const char *password, const char *recover_key)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(client_password_reset_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_password_reset_stmt, 1, password, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_password_reset_stmt, 2, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(client_password_reset_stmt, 3, recover_key, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(client_password_reset_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	if (sqlite3_changes(ldb) != 1) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_network_create(const char *email, const char *uid, const char *description,
	    const char *subnet, const char *netmask,
	    const char *embassy_certificate, const char *embassy_privatekey,
	    const char *passport_certificate, const char *passport_privatekey)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(network_create_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 1, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 2, uid, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 3, description, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 4, subnet, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 5, netmask, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 6, embassy_certificate, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 7, embassy_privatekey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 8, passport_certificate, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_create_stmt, 9, passport_privatekey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(network_create_stmt);
	if (ret != SQLITE_DONE) {
		line = __LINE__;
		goto error;
	}

	if (sqlite3_changes(ldb) != 1) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_network_get(const char *email, const char *description,
	    const unsigned char **uid, const unsigned char **subnet, const unsigned char **netmask)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(network_get_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_get_stmt, 1, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_get_stmt, 2, description, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_step(network_get_stmt);
	if (ret != SQLITE_ROW) {
		line = __LINE__;
		goto error;
	}

	*uid = sqlite3_column_text(network_get_stmt, 0);
	*subnet = sqlite3_column_text(network_get_stmt, 1);
	*netmask = sqlite3_column_text(network_get_stmt, 2);

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_network_list(const char *email, const char *apikey,
	int (*cb)(const unsigned char *, const unsigned char *, void *),
	void *store)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(network_list_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_list_stmt, 1, email, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_list_stmt, 2, apikey, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	//printf("expand: %s\n", sqlite3_expanded_sql(network_list_stmt));

	/* We don't distinguish between a client without a network
	 * and bad credentials.
	 */
	while (sqlite3_step(network_list_stmt) == SQLITE_ROW) {
		cb(sqlite3_column_text(network_list_stmt, 0),
		    sqlite3_column_text(network_list_stmt, 1),
		    store);
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

int
ldb_network_embassy_get(const char *uid, const unsigned char **embassy_passport,
	const unsigned char **embassy_privatekey, int *embassy_serial)
{
	int	ret;
	int	line;

	ret = sqlite3_reset(network_embassy_get_stmt);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_bind_text(network_embassy_get_stmt, 1, uid, -1, NULL);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	printf("expand: %s\n", sqlite3_expanded_sql(network_embassy_get_stmt));

	ret = sqlite3_step(network_embassy_get_stmt);
	if (ret != SQLITE_ROW) {
		line = __LINE__;
		goto error;
	}

	*embassy_passport = sqlite3_column_text(network_embassy_get_stmt, 0);
	*embassy_privatekey = sqlite3_column_text(network_embassy_get_stmt, 1);
	*embassy_serial = sqlite3_column_int(network_embassy_get_stmt, 2);

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	return (-1);
}

void
ldb_fini()
{
	sqlite3_finalize(client_create_stmt);
	client_create_stmt = NULL;

	sqlite3_close(ldb);
	ldb = NULL;
}

int
ldb_init(const char *filename)
{
	int	ret;
	int	line;

	ret = sqlite3_open(filename, &ldb);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, client_create_sql, -1, &client_create_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, client_activate_sql, -1, &client_activate_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, client_apikey_set_sql, -1, &client_apikey_set_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, client_apikey_reset_sql, -1, &client_apikey_reset_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, client_recover_sql, -1, &client_recover_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, client_password_reset_sql, -1, &client_password_reset_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, network_create_sql, -1, &network_create_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, network_get_sql, -1, &network_get_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, network_list_sql, -1, &network_list_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	ret = sqlite3_prepare_v2(ldb, network_embassy_get_sql, -1, &network_embassy_get_stmt, 0);
	if (ret != SQLITE_OK) {
		line = __LINE__;
		goto error;
	}

	return (0);
error:
	fprintf(stderr, "line:%d %s: ret=%d, changes=%d, %s\n", line, __func__, ret, sqlite3_changes(ldb), sqlite3_errmsg(ldb));
	ldb_fini();
	return (-1);
}

int
network_list_cb(const unsigned char *uid, const unsigned char *description, void *store)
{
	printf("network_list_cb> uid:%s, description:%s\n", uid, description);

	return (0);
}

int
main(void)
{
	int	ret;

	printf("%s\n", sqlite3_libversion());

	ret = ldb_init("test.db");
	printf("ldb_init: %d\n", ret);

	ldb_client_create("my_email", "my_password", "my_apikey");
	ldb_client_activate("my_email", "my_apikey");
	ldb_client_apikey_set("my_email", "my_password", "set_apikey");
	ldb_client_apikey_reset("my_email", "set_apikey", "reset_apikey");
	ldb_client_recover("my_email", "my_recover_key");
	ldb_client_password_reset("my_email", "new_password", "my_recover_key");

	ldb_network_create("my_email", "my_uid", "my_description", "my_subnet", "my_netmask",
	    "my_embassy_certificate", "my_embassy_privatekey",
	    "my_passport_certificate", "my_passport_privatekey");

	const unsigned char *uid = NULL;
	const unsigned char *subnet = NULL;
	const unsigned char *netmask = NULL;

	ldb_network_get("my_email", "my_description", &uid, &subnet, &netmask);
	printf("uid: %s, subnet: %s, netmask: %s\n", uid, subnet, netmask);

	ldb_network_list("my_email", "reset_apikey", network_list_cb, NULL);

	const unsigned char *embassy_passport = NULL;
	const unsigned char *embassy_privatekey = NULL;
	int embassy_serial;

	ldb_network_embassy_get("my_uid", &embassy_passport, &embassy_privatekey, &embassy_serial);
	printf("passport: %s, privatekey:%s, serial:%d\n", embassy_passport, embassy_privatekey, embassy_serial);


	ldb_fini();

	return 0;
}
