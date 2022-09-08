#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "mysql_api.h"
#include "mysql_tables.h"

#define __MYSQL_DEBUG
#define __MYSQL_DEBUG_FILE "/var/log/mysql.log"

#ifdef __MYSQL_DEBUG
#define LOG(format, ...) \
    do { \
        FILE *fp = fopen(__MYSQL_DEBUG_FILE, "a+"); \
        if (fp == NULL) { \
            break; \
        } \
        fprintf(fp, format, ##__VA_ARGS__); \
        fclose(fp); \
    } while(0)
#else
#define LOG(format, ...)
#endif

#define SQL_HOST        NULL
#define SQL_USER        NULL
#define SQL_PASSWD      NULL
#define SQL_PORT        0
#define SQL_SOCKET      "/tmp/mysql.sock"
#define SQL_CLNT_FLAG   0

#define SIZEOFARRAY(a)    (sizeof((a)) / sizeof((a)[0]))

char *sql_dbs[] = {
	SQL_DB,
};

sql_tables_t sql_tables[] = {
	AUDIT_MAIN_TABLE,
	AUDIT_MODBUS_TABLE,
	AUDIT_DNP3_TABLE,
	AUDIT_TRDP_TABLE,
	AUDIT_ENIP_TABLE,
	AUDIT_HTTP1_TABLE,
	AUDIT_FTP_TABLE,
	AUDIT_TELNET_TABLE,
	STUDY_MODBUS_TABLE,
	STUDY_DNP3_TABLE,
	STUDY_TRDP_TABLE,
	STUDY_ENIP_TABLE,
};

int sql_database_init(void)
{
	int status = SQL_SUCCESS, len;
	sql_handle handle;
	char query[SQL_QUERY_SIZE] = {0};

	handle = sql_db_connect(NULL);
	if (handle == NULL) {
		LOG("%s: connect mysql database error.\n", __func__);
		status = SQL_FAILED;
		goto out;
	}
	for (int i = 0; i < SIZEOFARRAY(sql_dbs); i++) {
		len = snprintf(query, sizeof(query), "CREATE DATABASE IF NOT EXISTS %s", sql_dbs[i]);
		status = sql_real_query(handle, query, len);
		if (status != SQL_SUCCESS) {
			LOG("%s: create database %s error.\n", __func__, sql_dbs[i]);
			status = SQL_FAILED;
			goto out;
		}
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return status;
}

int sql_tables_init(const char *db_name)
{
	int status = SQL_SUCCESS;
	sql_handle handle;
	
	handle = sql_db_connect(db_name);
	if (handle == NULL) {
		LOG("%s: connect mysql database error.\n", __func__);
		status = SQL_FAILED;
		goto out;
	}
	for (int i = 0; i < SIZEOFARRAY(sql_tables); i++) {
		status = sql_real_query(handle, sql_tables[i].create_string, strlen(sql_tables[i].create_string));
		if (status != SQL_SUCCESS) {
			LOG("%s: create table %s error.\n", __func__, sql_tables[i].table_name);
			status = SQL_FAILED;
			goto out;
		}
	}
	for (int i = 0; i < SIZEOFARRAY(sql_tables); i++) {
		if (sql_tables[i].sql_alter_table_handler != NULL) {
			status = (* sql_tables[i].sql_alter_table_handler)(handle);
			if (status != SQL_SUCCESS) {
				LOG("%s: alter table %s error.\n", __func__, sql_tables[i].table_name);
				status = SQL_FAILED;
				goto out;
			}
		}
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return status;
}

sql_handle sql_db_connect(const char *db_name)
{
	sql_handle handle;

	handle = mysql_init(NULL);
	if (handle == NULL) {
		LOG("%s: failed to initialize mysql object\n", __func__);
		goto out;
	}
	if (mysql_real_connect(handle, SQL_HOST, SQL_USER, SQL_PASSWD, db_name, SQL_PORT, SQL_SOCKET, SQL_CLNT_FLAG) == NULL) {
		LOG("%s: %s\n", __func__, mysql_error(handle));
		mysql_close(handle);
		handle = NULL;
		goto out;
	}
out:
	return handle;
}

void sql_db_disconnect(sql_handle handle)
{
	mysql_close(handle);
	return;
}

int sql_real_query(sql_handle handle, const char *qbuf, int len)
{
	int status = SQL_SUCCESS;

	status = mysql_real_query(handle, qbuf, len);
	if (status != SQL_SUCCESS) {
		LOG("%s: [%s] %s\n", __func__, qbuf, mysql_error(handle));
		status = SQL_FAILED;
	}
	return status;
}

