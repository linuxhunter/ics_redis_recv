#ifndef MYSQL_TABLE_H
#define MYSQL_TABLE_H

#define SQL_TABLE_DROP(t) \
	"DROP TABLE IF EXISTS "#t" "

#define AUDIT_MAIN_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"create_datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"modified_datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," \
	"src_mac VARCHAR(20)," \
	"dst_mac VARCHAR(20)," \
	"src_ip INT UNSIGNED NOT NULL," \
	"dst_ip INT UNSIGNED NOT NULL," \
	"src_port SMALLINT UNSIGNED NOT NULL," \
	"dst_port SMALLINT UNSIGNED NOT NULL," \
	"proto SMALLINT UNSIGNED NOT NULL," \
	"alproto INT UNSIGNED NOT NULL," \
	"pktlen BIGINT UNSIGNED NOT NULL," \
	"payload_len BIGINT UNSIGNED NOT NULL," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"UNIQUE INDEX flow_hash_index(flow_hash) USING BTREE,"\
	"INDEX datetime_index (create_datetime,modified_datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_MAIN_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, proto, " \
	"alproto, pktlen, payload_len, flow_hash) " \
	"VALUES (NULL,"

#define AUDIT_MODBUS_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"funcode SMALLINT UNSIGNED NOT NULL," \
	"r_address SMALLINT UNSIGNED," \
	"r_quantity SMALLINT UNSIGNED," \
	"w_address SMALLINT UNSIGNED," \
	"w_quantity SMALLINT UNSIGNED," \
	"subfunc SMALLINT UNSIGNED," \
	"and_mask SMALLINT UNSIGNED," \
	"or_mask SMALLINT UNSIGNED," \
	"data_len TINYINT UNSIGNED," \
	"data VARBINARY(255)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_MODBUS_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"funcode, r_address, r_quantity, w_address, w_quantity, subfunc, and_mask, or_mask, data_len, data ) " \
	"VALUES (NULL,"

#define AUDIT_DNP3_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"funcode SMALLINT UNSIGNED NOT NULL," \
	"object_counts INT UNSIGNED NOT NULL," \
	"object_length INT NOT NULL," \
	"objects VARBINARY(1024)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_DNP3_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"funcode, object_counts, object_length, objects ) " \
	"VALUES (NULL,"

#define AUDIT_TRDP_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"packet_type TINYINT UNSIGNED NOT NULL," \
	"sequence_counter INT UNSIGNED NOT NULL," \
	"protocol_version SMALLINT UNSIGNED NOT NULL," \
	"msg_type SMALLINT UNSIGNED NOT NULL," \
	"com_id INT UNSIGNED NOT NULL," \
	"ebt_topo_cnt INT UNSIGNED NOT NULL," \
	"op_trn_topo_cnt INT UNSIGNED NOT NULL," \
	"dataset_length INT UNSIGNED NOT NULL," \
	"reply_com_id INT UNSIGNED NOT NULL," \
	"reply_ip_address INT UNSIGNED NOT NULL," \
	"frame_checksum INT UNSIGNED NOT NULL," \
	"data VARBINARY(4096)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_TRDP_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"packet_type, sequence_counter, protocol_version, msg_type, com_id, ebt_topo_cnt, " \
	"op_trn_topo_cnt, dataset_length, reply_com_id, reply_ip_address, " \
	"frame_checksum, data ) " \
	"VALUES (NULL,"

#define AUDIT_ENIP_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"command SMALLINT UNSIGNED NOT NULL," \
	"session INT UNSIGNED NOT NULL," \
	"conn_id INT UNSIGNED NOT NULL," \
	"cip_service_counts SMALLINT UNSIGNED," \
	"cip_services VARCHAR(4096)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_ENIP_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"command, session, conn_id, cip_service_counts, cip_services ) " \
	"VALUES (NULL,"

#define AUDIT_HTTP1_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"uri_len INT UNSIGNED NOT NULL," \
	"uri VARCHAR(1024)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_HTTP1_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"uri_len, uri ) " \
	"VALUES (NULL,"

#define AUDIT_FTP_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"command_length SMALLINT UNSIGNED NOT NULL," \
	"command VARCHAR(255)," \
	"params_length INT UNSIGNED," \
	"params VARCHAR(1024)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_FTP_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"command_length, command, params_length, params ) " \
	"VALUES (NULL,"

#define AUDIT_TELNET_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"flow_hash INT UNSIGNED NOT NULL," \
	"payload_len SMALLINT UNSIGNED NOT NULL," \
	"data_length SMALLINT UNSIGNED NOT NULL," \
	"data VARCHAR(8192)," \
	"INDEX datetime_index (datetime) USING BTREE," \
	"PRIMARY KEY(id)" \
	") "

#define AUDIT_TELNET_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, flow_hash, payload_len, " \
	"data_length, data ) " \
	"VALUES (NULL,"

#define STUDY_MODBUS_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"src_ip INT UNSIGNED NOT NULL," \
	"dst_ip INT UNSIGNED NOT NULL," \
	"proto SMALLINT UNSIGNED NOT NULL," \
	"funcode SMALLINT UNSIGNED NOT NULL," \
	"address INT UNSIGNED NOT NULL," \
	"quantity INT UNSIGNED NOT NULL," \
	"template_id INT NOT NULL," \
	"INDEX unique_index(src_ip,dst_ip,proto,funcode,address,quantity,template_id) USING BTREE," \
	"PRIMARY KEY(id,template_id)" \
	") "

#define STUDY_MODBUS_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, src_ip, dst_ip, proto, " \
	"funcode, address, quantity, template_id ) " \
	"VALUES (NULL,"

#define STUDY_DNP3_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"src_ip INT UNSIGNED NOT NULL," \
	"dst_ip INT UNSIGNED NOT NULL," \
	"proto SMALLINT UNSIGNED NOT NULL," \
	"funcode SMALLINT UNSIGNED NOT NULL," \
	"groups SMALLINT UNSIGNED NOT NULL," \
	"variation SMALLINT UNSIGNED NOT NULL," \
	"indexes INT UNSIGNED NOT NULL," \
	"size INT UNSIGNED NOT NULL," \
	"template_id INT NOT NULL," \
	"INDEX unique_index(src_ip,dst_ip,proto,funcode,groups,variation,indexes,size,template_id) USING BTREE," \
	"PRIMARY KEY(id,template_id)" \
	") "

#define STUDY_DNP3_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, src_ip, dst_ip, proto, " \
	"funcode, groups, variation, indexes, size, template_id ) " \
	"VALUES (NULL,"

#define STUDY_TRDP_TABLE_CREATE(t) \
	"CREATE TABLE IF NOT EXISTS " #t " (" \
	"id INT UNSIGNED NOT NULL AUTO_INCREMENT," \
	"datetime DATETIME NULL DEFAULT CURRENT_TIMESTAMP," \
	"src_ip INT UNSIGNED NOT NULL," \
	"dst_ip INT UNSIGNED NOT NULL," \
	"proto SMALLINT UNSIGNED NOT NULL," \
	"packet_type TINYINT UNSIGNED NOT NULL," \
	"protocol_version SMALLINT UNSIGNED NOT NULL," \
	"msg_type SMALLINT UNSIGNED NOT NULL," \
	"com_id INT UNSIGNED NOT NULL," \
	"template_id INT NOT NULL," \
	"INDEX unique_index(src_ip,dst_ip,proto,packet_type,protocol_version,msg_type,com_id,template_id) USING BTREE," \
	"PRIMARY KEY(id,template_id)" \
	") "

#define STUDY_TRDP_TABLE_INSERT(t) \
	"INSERT INTO " #t "(id, src_ip, dst_ip, proto, " \
	"packet_type, protocol_version, msg_type, com_id, template_id ) " \
	"VALUES (NULL,"

#define AUDIT_MAIN_TABLE \
	{	"audit_main_table", \
		AUDIT_MAIN_TABLE_CREATE(audit_main_table), \
		AUDIT_MAIN_TABLE_INSERT(audit_main_table), \
		SQL_TABLE_DROP(audit_main_table), \
		NULL \
	}

#define AUDIT_MODBUS_TABLE \
	{	"audit_modbus_table", \
		AUDIT_MODBUS_TABLE_CREATE(audit_modbus_table), \
		AUDIT_MODBUS_TABLE_INSERT(audit_modbus_table), \
		SQL_TABLE_DROP(audit_modbus_table), \
		NULL \
	}

#define AUDIT_DNP3_TABLE \
	{	"audit_dnp3_table", \
		AUDIT_DNP3_TABLE_CREATE(audit_dnp3_table), \
		AUDIT_DNP3_TABLE_INSERT(audit_dnp3_table), \
		SQL_TABLE_DROP(audit_dnp3_table), \
		NULL \
	}

#define AUDIT_TRDP_TABLE \
	{	"audit_trdp_table", \
		AUDIT_TRDP_TABLE_CREATE(audit_trdp_table), \
		AUDIT_TRDP_TABLE_INSERT(audit_trdp_table), \
		SQL_TABLE_DROP(audit_trdp_table), \
		NULL \
	}

#define AUDIT_ENIP_TABLE \
	{	"audit_enip_table", \
		AUDIT_ENIP_TABLE_CREATE(audit_enip_table), \
		AUDIT_ENIP_TABLE_INSERT(audit_enip_table), \
		SQL_TABLE_DROP(audit_enip_table), \
		NULL \
	}

#define AUDIT_HTTP1_TABLE \
	{	"audit_http1_table", \
		AUDIT_HTTP1_TABLE_CREATE(audit_http1_table), \
		AUDIT_HTTP1_TABLE_INSERT(audit_http1_table), \
		SQL_TABLE_DROP(audit_http1_table), \
		NULL \
	}

#define AUDIT_FTP_TABLE \
	{	"audit_ftp_table", \
		AUDIT_FTP_TABLE_CREATE(audit_ftp_table), \
		AUDIT_FTP_TABLE_INSERT(audit_ftp_table), \
		SQL_TABLE_DROP(audit_ftp_table), \
		NULL \
	}

#define AUDIT_TELNET_TABLE \
	{	"audit_telnet_table", \
		AUDIT_TELNET_TABLE_CREATE(audit_telnet_table), \
		AUDIT_TELNET_TABLE_INSERT(audit_telnet_table), \
		SQL_TABLE_DROP(audit_telnet_table), \
		NULL \
	}

#define STUDY_MODBUS_TABLE \
	{	"study_modbus_table", \
		STUDY_MODBUS_TABLE_CREATE(study_modbus_table), \
		STUDY_MODBUS_TABLE_INSERT(study_modbus_table), \
		SQL_TABLE_DROP(study_modbus_table), \
		NULL \
	}

#define STUDY_DNP3_TABLE \
	{	"study_dnp3_table", \
		STUDY_DNP3_TABLE_CREATE(study_dnp3_table), \
		STUDY_DNP3_TABLE_INSERT(study_dnp3_table), \
		SQL_TABLE_DROP(study_dnp3_table), \
		NULL \
	}

#define STUDY_TRDP_TABLE \
	{	"study_trdp_table", \
		STUDY_TRDP_TABLE_CREATE(study_trdp_table), \
		STUDY_TRDP_TABLE_INSERT(study_trdp_table), \
		SQL_TABLE_DROP(study_trdp_table), \
		NULL \
	}

#endif
