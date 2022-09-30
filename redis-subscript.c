#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include <pthread.h>
#include <string.h>
#include <tlv_box.h>
#include <arpa/inet.h>

#include "redis-subscript.h"
#include "mysql_api.h"

extern sql_tables_t sql_tables[];

static int write_audit_main_data(sql_handle handle, audit_common_data_t *common_data, ics_proto_t ics_proto)
{
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;
	char eth_addr[ETH_ADDR_STRING_LEN] = {0};

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_MAIN_TABLE_INDEX].insert_string);
	end = query + len;

	snprintf(eth_addr, sizeof(eth_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
		common_data->smac[0], common_data->smac[1],
		common_data->smac[2], common_data->smac[3],
		common_data->smac[4], common_data->smac[5]);
	SQL_COPY_N_ESCAPE_STRING(eth_addr);
	SQL_FS;
	snprintf(eth_addr, sizeof(eth_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
		common_data->dmac[0], common_data->dmac[1],
		common_data->dmac[2], common_data->dmac[3],
		common_data->dmac[4], common_data->dmac[5]);
	SQL_COPY_N_ESCAPE_STRING(eth_addr);
	SQL_FS;
	SQL_COPY_UNUMBER(common_data->sip);
	SQL_FS;
	SQL_COPY_UNUMBER(common_data->dip);
	SQL_FS;
	SQL_COPY_NUMBER(common_data->sp);
	SQL_FS;
	SQL_COPY_NUMBER(common_data->dp);
	SQL_FS;
	SQL_COPY_NUMBER(common_data->proto);
	SQL_FS;
	SQL_COPY_NUMBER(ics_proto);
	SQL_FS;
	SQL_COPY_UNUMBER(common_data->pktlen);
	SQL_FS;
	SQL_COPY_UNUMBER(common_data->payload_len);
	SQL_FS;
	SQL_COPY_UNUMBER(common_data->flow_hash);
	SQL_EOQ;
	len = snprintf(end, sizeof(query)-(end-query), " on duplicate key update pktlen=pktlen+%u,payload_len=payload_len+%u ",
		common_data->pktlen,
		common_data->payload_len);
	end += len;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	return 0;
}

static void handle_audit_common_data(tlv_box_t *parsedBox, audit_common_data_t *audit_common_data)
{
	char eth_addr[ETH_ADDR_STRING_LEN] = {0};
	int eth_addr_length= sizeof(eth_addr);

	tlv_box_get_string(parsedBox, SRC_MAC, eth_addr, &eth_addr_length);
	sscanf(eth_addr, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		&audit_common_data->smac[0], &audit_common_data->smac[1],
		&audit_common_data->smac[2], &audit_common_data->smac[3],
		&audit_common_data->smac[4], &audit_common_data->smac[5]);
	eth_addr_length = sizeof(eth_addr);
	tlv_box_get_string(parsedBox, DST_MAC, eth_addr, &eth_addr_length);
	sscanf(eth_addr, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		&audit_common_data->dmac[0], &audit_common_data->dmac[1],
		&audit_common_data->dmac[2], &audit_common_data->dmac[3],
		&audit_common_data->dmac[4], &audit_common_data->dmac[5]);
	tlv_box_get_uint(parsedBox, SRC_IPv4, &audit_common_data->sip);
	tlv_box_get_uint(parsedBox, DST_IPv4, &audit_common_data->dip);
	tlv_box_get_ushort(parsedBox, SRC_PORT, &audit_common_data->sp);
	tlv_box_get_ushort(parsedBox, DST_PORT, &audit_common_data->dp);
	tlv_box_get_uchar(parsedBox, PROTO, &audit_common_data->proto);
	tlv_box_get_uint(parsedBox, FLOW_HASH, &audit_common_data->flow_hash);
	tlv_box_get_uint(parsedBox, PKTLEN, &audit_common_data->pktlen);
	tlv_box_get_ushort(parsedBox, PAYLOAD_LEN, &audit_common_data->payload_len);
	return;
}

int write_audit_modbus_data(audit_common_data_t *audit_common_data, ics_modbus_t *audit_modbus_data)
{
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;
	uint8_t funcode, data_len = 0, *data = NULL;
	uint16_t r_address = 0, r_quantity = 0, w_address = 0, w_quantity = 0, subfunc = 0, and_mask = 0, or_mask = 0;

	funcode = audit_modbus_data->funcode;
	switch(funcode) {
		case 1:
		case 2:
		case 3:
		case 4:
			r_address = audit_modbus_data->u.addr_quan.address;
			r_quantity = audit_modbus_data->u.addr_quan.quantity;
			break;
		case 5:
		case 6:
			w_address = audit_modbus_data->u.addr_data.address;
			data_len = 2;
			data = (uint8_t *)&audit_modbus_data->u.addr_data.data;
			break;
		case 8:
			subfunc = audit_modbus_data->u.subfunc.subfunction;
			break;
		case 15:
			w_address = audit_modbus_data->u.addr_quan_data.address;
			w_quantity = audit_modbus_data->u.addr_quan_data.quantity;
			data_len = audit_modbus_data->u.addr_quan_data.data_len;
			data = audit_modbus_data->u.addr_quan_data.data;
			break;
		case 16:
			w_address = audit_modbus_data->u.addr_quan.address;
			w_quantity = audit_modbus_data->u.addr_quan.quantity;
			break;
		case 22:
			and_mask = audit_modbus_data->u.and_or_mask.and_mask;
			or_mask = audit_modbus_data->u.and_or_mask.or_mask;
			break;
		case 23:
			r_address = audit_modbus_data->u.rw_addr_quan.read_address;
			r_quantity = audit_modbus_data->u.rw_addr_quan.read_quantity;
			w_address = audit_modbus_data->u.rw_addr_quan.write_address;
			w_quantity = audit_modbus_data->u.rw_addr_quan.write_quantity;
			break;
		default:
			goto out;
	}

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, audit_common_data, MODBUS);

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_MODBUS_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(audit_common_data->flow_hash);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_common_data->payload_len);
	SQL_FS;
	SQL_COPY_NUMBER(funcode);
	SQL_FS;
	SQL_COPY_NUMBER(r_address);
	SQL_FS;
	SQL_COPY_NUMBER(r_quantity);
	SQL_FS;
	SQL_COPY_NUMBER(w_address);
	SQL_FS;
	SQL_COPY_NUMBER(w_quantity);
	SQL_FS;
	SQL_COPY_NUMBER(subfunc);
	SQL_FS;
	SQL_COPY_NUMBER(and_mask);
	SQL_FS;
	SQL_COPY_NUMBER(or_mask);
	SQL_FS;
	SQL_COPY_NUMBER(data_len);
	SQL_FS;
	if (data != NULL) {
		SQL_COPY_BINARY(data, data_len);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_modbus_data(tlv_box_t *parsedBox)
{
	audit_common_data_t audit_common_data;
	ics_modbus_t audit_modbus_data;
	int audit_modbus_data_length;

	memset(&audit_common_data, 0x00, sizeof(audit_common_data));
	memset(&audit_modbus_data, 0x00, sizeof(audit_modbus_data));

	handle_audit_common_data(parsedBox, &audit_common_data);
	audit_modbus_data_length = sizeof(audit_modbus_data);
	tlv_box_get_bytes(parsedBox, MODBUS_AUDIT_DATA, (unsigned char *)&audit_modbus_data, &audit_modbus_data_length);
	write_audit_modbus_data(&audit_common_data, &audit_modbus_data);
	return 0;
}

int check_study_data_unique(sql_handle handle, int db_index, study_common_data_t *common_data, void *study_data)
{
	int status = 0, len;
	char query[SQL_QUERY_SIZE] = {0};
	unsigned int rows = 0;
	MYSQL_RES *results=NULL;

	switch(db_index) {
		case STUDY_MODBUS_TABLE_INDEX:
			{
				modbus_ht_item_t *modbus_data = (modbus_ht_item_t *)study_data;
				len = snprintf(query, sizeof(query), "select id from %s where src_ip=%u AND dst_ip=%u AND proto=%u AND funcode=%u AND address=%u AND quantity=%u AND template_id=%d ",
					sql_tables[db_index].table_name,
					common_data->sip,
					common_data->dip,
					common_data->proto,
					modbus_data->funcode,
					modbus_data->address,
					modbus_data->quantity,
					common_data->template_id);
			}
			break;
		case STUDY_DNP3_TABLE_INDEX:
			{
				study_dnp3_data_t *dnp3_data = (study_dnp3_data_t *)study_data;
				len = snprintf(query, sizeof(query), "select id from %s where src_ip=%u AND dst_ip=%u AND proto=%u AND funcode=%u AND groups=%u AND variation=%u AND indexes=%u AND size=%u AND template_id=%d ",
					sql_tables[db_index].table_name,
					dnp3_data->common.sip,
					dnp3_data->common.dip,
					dnp3_data->common.proto,
					dnp3_data->funcode,
					dnp3_data->group,
					dnp3_data->variation,
					dnp3_data->index,
					dnp3_data->size,
					dnp3_data->common.template_id);
			}
			break;
		case STUDY_TRDP_TABLE_INDEX:
			{
				trdp_ht_item_t *trdp_data = (trdp_ht_item_t *)study_data;
				len = snprintf(query, sizeof(query), "select id from %s where src_ip=%u AND dst_ip=%u AND proto=%u AND packet_type=%u AND protocol_version=%u AND msg_type=%u AND com_id=%u AND template_id=%d ",
					sql_tables[db_index].table_name,
					common_data->sip,
					common_data->dip,
					common_data->proto,
					trdp_data->packet_type,
					trdp_data->protocol_version,
					trdp_data->msg_type,
					trdp_data->com_id,
					common_data->template_id);
			}
			break;
		case STUDY_ENIP_TABLE_INDEX:
			{
				study_enip_data_t *enip_data = (study_enip_data_t *)study_data;
				len = snprintf(query, sizeof(query), "select id from %s where src_ip=%u AND dst_ip=%u AND proto=%u AND command=%u AND session=%u AND conn_id=%u AND service=%u AND class=%u AND template_id=%d ",
					sql_tables[db_index].table_name,
					enip_data->common.sip,
					enip_data->common.dip,
					enip_data->common.proto,
					enip_data->command,
					enip_data->session,
					enip_data->conn_id,
					enip_data->service,
					enip_data->class,
					enip_data->common.template_id);
			}
			break;
		default:
			goto out;
	}
	status = mysql_real_query(handle, query, len);
    if (status != 0) {
        status = -1;
        goto out;
    } else {
        results = mysql_store_result(handle);
        if (results) {
            rows = mysql_num_rows(results);
            if (rows == 0) {
                status = 0;
            } else {
                status = 1;
            }
            mysql_free_result(results);
        } else {
            status = -2;
        }
    }
out:
	return status;
}

int write_study_modbus_data(study_common_data_t *study_common_data, modbus_ht_item_t *study_modbus_data)
{
	int ret = SQL_SUCCESS;
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		ret = SQL_FAILED;
		goto out;
	}
	if (check_study_data_unique(handle, STUDY_MODBUS_TABLE_INDEX, study_common_data, (void *)study_modbus_data)) {
		//printf("duplicated modbus study data item!!!\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "%s", sql_tables[STUDY_MODBUS_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(study_common_data->sip);
	SQL_FS;
	SQL_COPY_UNUMBER(study_common_data->dip);
	SQL_FS;
	SQL_COPY_NUMBER(study_common_data->proto);
	SQL_FS;
	SQL_COPY_NUMBER(study_modbus_data->funcode);
	SQL_FS;
	SQL_COPY_NUMBER(study_modbus_data->address);
	SQL_FS;
	SQL_COPY_NUMBER(study_modbus_data->quantity);
	SQL_FS;
	SQL_COPY_NUMBER(study_common_data->template_id);
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return ret;
}

int handle_study_modbus_data(tlv_box_t *parsedBox)
{
	study_common_data_t study_common_data;
	modbus_ht_item_t study_modbus_data;
	int study_modbus_data_length = sizeof(modbus_ht_item_t);

	memset(&study_common_data, 0x00, sizeof(study_common_data));
	memset(&study_modbus_data, 0x00, sizeof(study_modbus_data));

	tlv_box_get_int(parsedBox, TEMPLATE_ID, &study_common_data.template_id);
	tlv_box_get_uint(parsedBox, SRC_IPv4, &study_common_data.sip);
	tlv_box_get_uint(parsedBox, DST_IPv4, &study_common_data.dip);
	tlv_box_get_uchar(parsedBox, PROTO, &study_common_data.proto);
	tlv_box_get_bytes(parsedBox, MODBUS_STUDY_DATA, (unsigned char *)&study_modbus_data, &study_modbus_data_length);
	write_study_modbus_data(&study_common_data, &study_modbus_data);
	return 0;
}

#define DNP3_DATA_BUFFER_LENGTH 2048
int write_audit_dnp3_data(audit_dnp3_data_t *dnp3_data)
{
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, &dnp3_data->common, DNP3);

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_DNP3_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(dnp3_data->common.flow_hash);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->common.payload_len);
	SQL_FS;
	SQL_COPY_NUMBER(dnp3_data->funcode);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->object_counts);
	SQL_FS;
	SQL_COPY_NUMBER(dnp3_data->object_length);
	SQL_FS;
	if (dnp3_data->object_length) {
		SQL_COPY_BINARY(dnp3_data->objects, dnp3_data->object_length);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_dnp3_data(tlv_box_t *parsedBox)
{
	audit_dnp3_data_t dnp3_audit_data;
	uint8_t audit_dnp3_buffer[DNP3_DATA_BUFFER_LENGTH] = {0};
	int audit_dnp3_buffer_length = DNP3_DATA_BUFFER_LENGTH, offset = 0;

	memset(&dnp3_audit_data, 0x00, sizeof(dnp3_audit_data));

	handle_audit_common_data(parsedBox, &dnp3_audit_data.common);
	tlv_box_get_bytes(parsedBox, DNP3_AUDIT_DATA, audit_dnp3_buffer, &audit_dnp3_buffer_length);
	dnp3_audit_data.funcode = audit_dnp3_buffer[offset];
	offset += sizeof(uint8_t);
	dnp3_audit_data.object_counts = *((uint32_t *)&audit_dnp3_buffer[offset]);
	offset += sizeof(uint32_t);
	dnp3_audit_data.object_length = audit_dnp3_buffer_length - offset;
	dnp3_audit_data.objects = audit_dnp3_buffer + offset;
	write_audit_dnp3_data(&dnp3_audit_data);
	return 0;
}

int write_audit_trdp_data(audit_common_data_t *audit_common_data, ics_trdp_t *audit_trdp_data)
{
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, audit_common_data, TRDP);

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_TRDP_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(audit_common_data->flow_hash);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_common_data->payload_len);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->packet_type);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.sequence_counter);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.protocol_version);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.msg_type);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.com_id);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.ebt_topo_cnt);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.op_trn_topo_cnt);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.dataset_length);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.reply_com_id);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.reply_ip_address);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_trdp_data->u.pd.header.frame_checksum);
	SQL_FS;
	if (audit_trdp_data->u.pd.header.dataset_length) {
		SQL_COPY_BINARY(audit_trdp_data->u.pd.data, audit_trdp_data->u.pd.header.dataset_length);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_trdp_data(tlv_box_t *parsedBox)
{
	audit_common_data_t audit_common_data;
	ics_trdp_t audit_trdp_data;
	int trdp_data_length = sizeof(ics_trdp_t);

	memset(&audit_common_data, 0x00, sizeof(audit_common_data));
	memset(&audit_trdp_data, 0x00, sizeof(audit_trdp_data));

	handle_audit_common_data(parsedBox, &audit_common_data);
	tlv_box_get_bytes(parsedBox, TRDP_AUDIT_DATA, (unsigned char *)&audit_trdp_data, &trdp_data_length);
	write_audit_trdp_data(&audit_common_data, &audit_trdp_data);
	return 0;
}

int write_study_trdp_data(study_common_data_t *study_common_data, trdp_ht_item_t *study_trdp_data)
{
	int ret = SQL_SUCCESS;
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		ret = SQL_FAILED;
		goto out;
	}
	if (check_study_data_unique(handle, STUDY_TRDP_TABLE_INDEX, study_common_data, (void *)study_trdp_data)) {
		//printf("duplicated trdp study data item!!!\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "%s", sql_tables[STUDY_TRDP_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(study_common_data->sip);
	SQL_FS;
	SQL_COPY_UNUMBER(study_common_data->dip);
	SQL_FS;
	SQL_COPY_NUMBER(study_common_data->proto);
	SQL_FS;
	SQL_COPY_UNUMBER(study_trdp_data->packet_type);
	SQL_FS;
	SQL_COPY_UNUMBER(study_trdp_data->protocol_version);
	SQL_FS;
	SQL_COPY_UNUMBER(study_trdp_data->msg_type);
	SQL_FS;
	SQL_COPY_UNUMBER(study_trdp_data->com_id);
	SQL_FS;
	SQL_COPY_NUMBER(study_common_data->template_id);
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return ret;
}

int handle_study_trdp_data(tlv_box_t *parsedBox)
{
	study_common_data_t study_common_data;
	trdp_ht_item_t study_trdp_data;
	int study_trdp_data_length = sizeof(study_trdp_data);

	memset(&study_common_data, 0x00, sizeof(study_common_data));
	memset(&study_trdp_data, 0x00, sizeof(study_trdp_data));

	tlv_box_get_int(parsedBox, TEMPLATE_ID, &study_common_data.template_id);
	tlv_box_get_uint(parsedBox, SRC_IPv4, &study_common_data.sip);
	tlv_box_get_uint(parsedBox, DST_IPv4, &study_common_data.dip);
	tlv_box_get_uchar(parsedBox, PROTO, &study_common_data.proto);
	tlv_box_get_bytes(parsedBox, TRDP_STUDY_DATA, (unsigned char *)&study_trdp_data, &study_trdp_data_length);
	write_study_trdp_data(&study_common_data, &study_trdp_data);
	return 0;

}

int write_study_dnp3_data(study_dnp3_data_t *dnp3_data)
{
	int ret = SQL_SUCCESS;
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		ret = SQL_FAILED;
		goto out;
	}
	if (check_study_data_unique(handle, STUDY_DNP3_TABLE_INDEX, NULL, (void *)dnp3_data)) {
		//printf("duplicated dnp3 study data item!!!\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "%s", sql_tables[STUDY_DNP3_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(dnp3_data->common.sip);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->common.dip);
	SQL_FS;
	SQL_COPY_NUMBER(dnp3_data->common.proto);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->funcode);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->group);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->variation);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->index);
	SQL_FS;
	SQL_COPY_UNUMBER(dnp3_data->size);
	SQL_FS;
	SQL_COPY_NUMBER(dnp3_data->common.template_id);
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return ret;
}

int handle_study_dnp3_data(tlv_box_t *parsedBox)
{
	study_dnp3_data_t dnp3_data;
	uint8_t dnp3_study_data_buffer[DNP3_DATA_BUFFER_LENGTH] = {0};
	int dnp3_study_data_buffer_length = DNP3_DATA_BUFFER_LENGTH, offset = 0;
	uint32_t object_counts;

	memset(&dnp3_data, 0x00, sizeof(dnp3_data));
	tlv_box_get_int(parsedBox, TEMPLATE_ID, &dnp3_data.common.template_id);
	tlv_box_get_uint(parsedBox, SRC_IPv4, &dnp3_data.common.sip);
	tlv_box_get_uint(parsedBox, DST_IPv4, &dnp3_data.common.dip);
	tlv_box_get_uchar(parsedBox, PROTO, &dnp3_data.common.proto);
	tlv_box_get_bytes(parsedBox, DNP3_STUDY_DATA, dnp3_study_data_buffer, &dnp3_study_data_buffer_length);
	object_counts = *((uint32_t *)&dnp3_study_data_buffer[offset]);
	offset += sizeof(uint32_t);
	for (uint32_t i = 0; i < object_counts; i++) {
		memcpy(&dnp3_data.funcode, dnp3_study_data_buffer + offset, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		memcpy(&dnp3_data.group, dnp3_study_data_buffer + offset, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		memcpy(&dnp3_data.variation, dnp3_study_data_buffer + offset, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		memcpy(&dnp3_data.index, dnp3_study_data_buffer + offset, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		memcpy(&dnp3_data.size, dnp3_study_data_buffer + offset, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		write_study_dnp3_data(&dnp3_data);
	}
	return 0;
}

#define ENIP_DATA_BUFFER_LENGTH     4096
int write_study_enip_data(study_enip_data_t *enip_data)
{
	int ret = SQL_SUCCESS;
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		ret = SQL_FAILED;
		goto out;
	}
	if (check_study_data_unique(handle, STUDY_ENIP_TABLE_INDEX, NULL, (void *)enip_data)) {
		//printf("duplicated enip study data item!!!\n");
		goto out;
	}
	len = snprintf(query, sizeof(query), "%s", sql_tables[STUDY_ENIP_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(enip_data->common.sip);
	SQL_FS;
	SQL_COPY_UNUMBER(enip_data->common.dip);
	SQL_FS;
	SQL_COPY_NUMBER(enip_data->common.proto);
	SQL_FS;
	SQL_COPY_UNUMBER(enip_data->command);
	SQL_FS;
	SQL_COPY_UNUMBER(enip_data->session);
	SQL_FS;
	SQL_COPY_UNUMBER(enip_data->conn_id);
	SQL_FS;
	SQL_COPY_UNUMBER(enip_data->service);
	SQL_FS;
	SQL_COPY_UNUMBER(enip_data->class);
	SQL_FS;
	SQL_COPY_NUMBER(enip_data->common.template_id);
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
out:
	if (handle)
		sql_db_disconnect(handle);
	return ret;
}

int handle_study_enip_data(tlv_box_t *parsedBox)
{
	study_enip_data_t enip_data;
	uint8_t enip_study_data_buffer[ENIP_DATA_BUFFER_LENGTH] = {0};
	int enip_study_data_buffer_length = ENIP_DATA_BUFFER_LENGTH, offset = 0;
	uint32_t enip_counts;

	memset(&enip_data, 0x00, sizeof(enip_data));
	tlv_box_get_int(parsedBox, TEMPLATE_ID, &enip_data.common.template_id);
	tlv_box_get_uint(parsedBox, SRC_IPv4, &enip_data.common.sip);
	tlv_box_get_uint(parsedBox, DST_IPv4, &enip_data.common.dip);
	tlv_box_get_uchar(parsedBox, PROTO, &enip_data.common.proto);
	tlv_box_get_bytes(parsedBox, ENIP_STUDY_DATA, enip_study_data_buffer, &enip_study_data_buffer_length);
	enip_counts = *((uint32_t *)&enip_study_data_buffer[offset]);
	offset += sizeof(uint32_t);
	for (uint32_t i = 0; i < enip_counts; i++) {
		memcpy(&enip_data.command, enip_study_data_buffer + offset, sizeof(uint16_t));
		offset += sizeof(uint16_t);
		memcpy(&enip_data.session, enip_study_data_buffer + offset, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		memcpy(&enip_data.conn_id, enip_study_data_buffer + offset, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		memcpy(&enip_data.service, enip_study_data_buffer + offset, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		memcpy(&enip_data.class, enip_study_data_buffer + offset, sizeof(uint8_t));
		offset += sizeof(uint8_t);
		write_study_enip_data(&enip_data);
	}
	return 0;
}

int handle_warning_modbus_data(tlv_box_t *parsedBox)
{
	int template_id;
	modbus_ht_item_t warning_data;
	int warning_data_length = sizeof(modbus_ht_item_t);

	memset(&warning_data, 0x00, sizeof(warning_data));

	tlv_box_get_int(parsedBox, TEMPLATE_ID, &template_id);
	tlv_box_get_bytes(parsedBox, MODBUS_WARNING_DATA, (unsigned char *)&warning_data, &warning_data_length);
	printf("[Modbus][Warning]: template_id = %d, sip = %u, dip = %u, proto = %u, funcode = %u, address = %u, quantity = %u\n",
		template_id,
		warning_data.sip,
		warning_data.dip,
		warning_data.proto,
		warning_data.funcode,
		warning_data.address,
		warning_data.quantity);
	return 0;
}

int handle_warning_dnp3_data(tlv_box_t *parsedBox)
{
	int template_id;
	dnp3_ht_item_t warning_data;
	int warning_data_length = sizeof(dnp3_ht_item_t);

	memset(&warning_data, 0x00, sizeof(warning_data));
	tlv_box_get_int(parsedBox, TEMPLATE_ID, &template_id);
	tlv_box_get_bytes(parsedBox, DNP3_WARNING_DATA, (unsigned char *)&warning_data, &warning_data_length);
	printf("[DNP3][Warning]: template_id = %u, sip = %u, dip = %u, proto = %u, funcode = %u, group = %u, variation = %u, index = %u, size = %u\n",
		template_id,
		warning_data.sip,
		warning_data.dip,
		warning_data.proto,
		warning_data.funcode,
		warning_data.group,
		warning_data.variation,
		warning_data.index,
		warning_data.size);
	return 0;
}

int handle_warning_trdp_data(tlv_box_t *parsedBox)
{
	int template_id;
	trdp_ht_item_t warning_data;
	int warning_data_length = sizeof(trdp_ht_item_t);

	memset(&warning_data, 0x00, sizeof(warning_data));
	tlv_box_get_int(parsedBox, TEMPLATE_ID, &template_id);
	tlv_box_get_bytes(parsedBox, TRDP_WARNING_DATA, (unsigned char *)&warning_data, &warning_data_length);
	printf("[TRDP][Warning]: template_id = %u, sip = %u, dip = %u, proto = %u, packet_type = %u, protocol_version = %u, msg_type = %u, com_id = %u\n",
		template_id,
		warning_data.sip,
		warning_data.dip,
		warning_data.proto,
		warning_data.packet_type,
		warning_data.protocol_version,
		warning_data.msg_type,
		warning_data.com_id);
	return 0;
}

int handle_warning_enip_data(tlv_box_t *parsedBox)
{
	int template_id;
	enip_ht_item_t warning_data;
	int warning_data_length = sizeof(enip_ht_item_t);

	memset(&warning_data, 0x00, sizeof(warning_data));
	tlv_box_get_int(parsedBox, TEMPLATE_ID, &template_id);
	tlv_box_get_bytes(parsedBox, ENIP_WARNING_DATA, (unsigned char *)&warning_data, &warning_data_length);
	printf("[ENIP][Warning]: template_id = %u, sip = %u, dip = %u, proto = %u, command = %u, session = %u, conn_id = %u, service = %u, class = %u\n",
		template_id,
		warning_data.sip,
		warning_data.dip,
		warning_data.proto,
		warning_data.command,
		warning_data.session,
		warning_data.conn_id,
		warning_data.service,
		warning_data.class);
	return 0;
}

int handle_baseline_warning_data(uint8_t app_proto, ics_baseline_warning_data_t baseline_warning_data)
{
	printf("app_proto = %u, type = %u, std_min = %u, std_max = %u, real_value = %u\n",
		app_proto,
		baseline_warning_data.type,
		baseline_warning_data.std_min,
		baseline_warning_data.std_max,
		baseline_warning_data.real_value);
	return 0;
}

int write_audit_enip_data(audit_common_data_t *audit_common_data, ics_enip_t *audit_enip_data)
{
	sql_handle handle;
	int len, cip_service_len = 0;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;
	uint16_t enip_index;
	uint8_t cip_index;
	char cip_services_buffer[CIP_SERVICES_BUF_MAX] = {0};

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, audit_common_data, ENIP);

	for (enip_index = 0; enip_index < audit_enip_data->enip_service_count; enip_index++) {
		len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_ENIP_TABLE_INDEX].insert_string);
		end = query + len;

		SQL_COPY_UNUMBER(audit_common_data->flow_hash);
		SQL_FS;
		SQL_COPY_UNUMBER(audit_common_data->payload_len);
		SQL_FS;
		SQL_COPY_UNUMBER(audit_enip_data->enip_services[enip_index].command);
		SQL_FS;
		SQL_COPY_UNUMBER(audit_enip_data->enip_services[enip_index].session);
		SQL_FS;
		SQL_COPY_UNUMBER(audit_enip_data->enip_services[enip_index].conn_id);
		SQL_FS;
		SQL_COPY_UNUMBER(audit_enip_data->enip_services[enip_index].cip_service_count);
		SQL_FS;
		if (audit_enip_data->enip_services[enip_index].cip_service_count > 0) {
			for (cip_service_len = 0, cip_index = 0; cip_index < audit_enip_data->enip_services[enip_index].cip_service_count; cip_index++) {
				cip_service_len += snprintf(cip_services_buffer + cip_service_len, sizeof(cip_services_buffer) - cip_service_len,
					"service=%02x,class=%02x,instance=%02x,",
					audit_enip_data->enip_services[enip_index].cip_services[cip_index].service,
					audit_enip_data->enip_services[enip_index].cip_services[cip_index].class,
					audit_enip_data->enip_services[enip_index].cip_services[cip_index].instance);
			}
			cip_services_buffer[cip_service_len-1] = '\0';
			SQL_COPY_N_ESCAPE_STRING(cip_services_buffer);
		} else {
			SQL_COPY_NULL_ESCAPE_STRING();
		}
		SQL_EOQ;

		if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
			printf("running SQL [%s] error.\n", query);
		}
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_enip_data(tlv_box_t *parsedBox)
{
	audit_common_data_t audit_common_data;
	ics_enip_t audit_enip_data;
	int enip_data_length = sizeof(ics_enip_t);

	memset(&audit_common_data, 0x00, sizeof(audit_common_data));
	memset(&audit_enip_data, 0x00, sizeof(audit_enip_data));

	handle_audit_common_data(parsedBox, &audit_common_data);
	tlv_box_get_bytes(parsedBox, ENIP_AUDIT_DATA, (unsigned char *)&audit_enip_data, &enip_data_length);
	write_audit_enip_data(&audit_common_data, &audit_enip_data);
	return 0;
}


int write_audit_http1_data(audit_http1_data_t *audit_http1_data)
{
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, &audit_http1_data->common, HTTP1);

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_HTTP1_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(audit_http1_data->common.flow_hash);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_http1_data->common.payload_len);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_http1_data->http_uri_len);
	SQL_FS;
	if (audit_http1_data->http_uri_len) {
		SQL_COPY_N_ESCAPE_STRING(audit_http1_data->http_uri);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_http1_data(tlv_box_t *parsedBox)
{
	int ret = 0;
	audit_http1_data_t audit_http1_data;

	memset(&audit_http1_data, 0x00, sizeof(audit_http1_data));
	if ((audit_http1_data.http_uri = malloc(HTTP1_URI_SIZE)) == NULL) {
		ret = -1;
		goto out;
	}
	memset(audit_http1_data.http_uri, 0x00, HTTP1_URI_SIZE);
	audit_http1_data.http_uri_len = HTTP1_URI_SIZE;

	handle_audit_common_data(parsedBox, &audit_http1_data.common);
	tlv_box_get_bytes(parsedBox, HTTP1_AUDIT_DATA, (unsigned char *)audit_http1_data.http_uri, (int *)&audit_http1_data.http_uri_len);
	write_audit_http1_data(&audit_http1_data);
out:
	if (audit_http1_data.http_uri)
		free(audit_http1_data.http_uri);
	return ret;
}

int write_audit_ftp_data(audit_ftp_data_t *audit_ftp_data)
{
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, &audit_ftp_data->common, FTP);

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_FTP_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(audit_ftp_data->common.flow_hash);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_ftp_data->common.payload_len);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_ftp_data->command_length);
	SQL_FS;
	if (audit_ftp_data->command_length) {
		SQL_COPY_N_ESCAPE_STRING(audit_ftp_data->command);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_FS;
	SQL_COPY_UNUMBER(audit_ftp_data->params_length);
	SQL_FS;
	if (audit_ftp_data->params_length) {
		SQL_COPY_N_ESCAPE_STRING(audit_ftp_data->params);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_EOQ;
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_ftp_data(tlv_box_t *parsedBox)
{
	int ret = 0;
	tlv_box_t *inner_box;
	audit_ftp_data_t audit_ftp_data;
	int length;

	memset(&audit_ftp_data, 0x00, sizeof(audit_ftp_data));

	handle_audit_common_data(parsedBox, &audit_ftp_data.common);
	tlv_box_get_object(parsedBox, FTP_AUDIT_DATA, &inner_box);
	if (inner_box == NULL) {
		ret = -1;
		goto out;
	}
	tlv_box_get_uchar(inner_box, FTP_COMMAND_LENGTH, &audit_ftp_data.command_length);
	length = audit_ftp_data.command_length + 1;
	if ((audit_ftp_data.command = malloc(audit_ftp_data.command_length+1)) == NULL) {
		ret = -2;
		goto out;
	}
	memset(audit_ftp_data.command, 0x00, audit_ftp_data.command_length+1);
	tlv_box_get_string(inner_box, FTP_COMMAND, audit_ftp_data.command, &length);
	tlv_box_get_uint(inner_box, FTP_PARAMS_LENGTH, &audit_ftp_data.params_length);
	length = audit_ftp_data.params_length + 1;
	if ((audit_ftp_data.params = malloc(audit_ftp_data.params_length+1)) == NULL) {
		ret = -3;
		goto out;
	}
	memset(audit_ftp_data.params, 0x00, audit_ftp_data.params_length+1);
	tlv_box_get_string(inner_box, FTP_PARAMS, audit_ftp_data.params, &length);
	write_audit_ftp_data(&audit_ftp_data);
out:
	if (audit_ftp_data.command != NULL)
		free(audit_ftp_data.command);
	if (audit_ftp_data.params != NULL)
		free(audit_ftp_data.params);
	if (inner_box)
		tlv_box_destroy(inner_box);
	return ret;
}

int write_audit_telnet_data(audit_telnet_data_t *audit_telnet_data)
{
	sql_handle handle;
	int len;
	char query[SQL_QUERY_SIZE] = {0}, *end = NULL;

	handle = sql_db_connect(SQL_DB);
	if (handle == NULL) {
		printf("connect database %s error.\n", SQL_DB);
		goto out;
	}
	write_audit_main_data(handle, &audit_telnet_data->common, TELNET);

	len = snprintf(query, sizeof(query), "%s", sql_tables[AUDIT_TELNET_TABLE_INDEX].insert_string);
	end = query + len;

	SQL_COPY_UNUMBER(audit_telnet_data->common.flow_hash);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_telnet_data->common.payload_len);
	SQL_FS;
	SQL_COPY_UNUMBER(audit_telnet_data->data_length);
	SQL_FS;
	if (audit_telnet_data->data_length) {
		SQL_COPY_N_ESCAPE_STRING(audit_telnet_data->data);
	} else {
		SQL_COPY_NULL_ESCAPE_STRING();
	}
	SQL_EOQ;
	printf("query = %s\n", query);
	if (sql_real_query(handle, query, end - query) != SQL_SUCCESS) {
		printf("running SQL [%s] error.\n", query);
	}
	sql_db_disconnect(handle);
out:
	return 0;
}

int handle_audit_telnet_data(tlv_box_t *parsedBox)
{
	int ret = 0;
	tlv_box_t *inner_box;
	audit_telnet_data_t audit_telnet_data;
	int length;

	memset(&audit_telnet_data, 0x00, sizeof(audit_telnet_data));

	handle_audit_common_data(parsedBox, &audit_telnet_data.common);
	tlv_box_get_object(parsedBox, TELNET_AUDIT_DATA, &inner_box);
	if (inner_box == NULL) {
		ret = -1;
		goto out;
	}
	tlv_box_get_int(inner_box, TELNET_DATA_LENGTH, &audit_telnet_data.data_length);
	length = audit_telnet_data.data_length + 1;
	if ((audit_telnet_data.data = malloc(length)) == NULL) {
		ret = -2;
		goto out;
	}
	memset(audit_telnet_data.data, 0x00, length);
	tlv_box_get_bytes(inner_box, TELNET_DATA, (unsigned char *)audit_telnet_data.data, &length);
	write_audit_telnet_data(&audit_telnet_data);
out:
	if (audit_telnet_data.data != NULL)
		free(audit_telnet_data.data);
	if (inner_box)
		tlv_box_destroy(inner_box);
	return ret;
}

int handle_audit_data(char *args)
{
	int ret = 0;
	uint8_t *audit_data = (uint8_t *)args;
	int audit_data_len = 0;
	tlv_box_t *parsedBox = NULL;
	uint8_t app_proto = ICS_PROTO_MAX;

	sscanf((char *)audit_data, "%d:", &audit_data_len);
	audit_data = (uint8_t *)strchr((char *)audit_data, ':');
	audit_data++;

	parsedBox = tlv_box_parse(audit_data, audit_data_len);
	if (parsedBox == NULL) {
		ret = -1;
		goto out;
	}
	tlv_box_get_uchar(parsedBox, APP_PROTO, &app_proto);
	switch(app_proto) {
		case MODBUS:
			handle_audit_modbus_data(parsedBox);
			break;
		case DNP3:
			handle_audit_dnp3_data(parsedBox);
			break;
		case TRDP:
			handle_audit_trdp_data(parsedBox);
			break;
		case ENIP:
			handle_audit_enip_data(parsedBox);
			break;
		case HTTP1:
			handle_audit_http1_data(parsedBox);
			break;
		case FTP:
			handle_audit_ftp_data(parsedBox);
			break;
		case TELNET:
			handle_audit_telnet_data(parsedBox);
			break;
		default:
			break;
	}
out:
	if (parsedBox) {
		tlv_box_destroy(parsedBox);
	}
	return ret;
}

int handle_study_data(char *args)
{
	int ret = 0;
	uint8_t *study_data = (uint8_t *)args;
	int study_data_len = 0;
	tlv_box_t *parsedBox = NULL;
	uint8_t app_proto = 0;

	sscanf((char *)study_data, "%d:", &study_data_len);
	study_data = (uint8_t *)strchr((char *)study_data, ':');
	study_data++;
	parsedBox = tlv_box_parse(study_data, study_data_len);
	if (parsedBox == NULL) {
		ret = -1;
		goto out;
	}
	tlv_box_get_uchar(parsedBox, APP_PROTO, &app_proto);
	switch(app_proto) {
		case MODBUS:
			handle_study_modbus_data(parsedBox);
			break;
		case DNP3:
			handle_study_dnp3_data(parsedBox);
			break;
		case TRDP:
			handle_study_trdp_data(parsedBox);
			break;
		case ENIP:
			handle_study_enip_data(parsedBox);
			break;
		default:
			break;
	}
out:
	if (parsedBox) {
		tlv_box_destroy(parsedBox);
	}
	return ret;
}

int handle_warning_data(char *args)
{
	int ret = 0;
	uint8_t *warning_data = (uint8_t *)args;
	int warning_data_len = 0;
	tlv_box_t *parsedBox = NULL;
	uint8_t app_proto = 0;
	ics_baseline_warning_data_t baseline_warning_data;
	int baseline_warning_data_length = sizeof(ics_baseline_warning_data_t);

	sscanf((char *)warning_data, "%d:", &warning_data_len);
	warning_data = (uint8_t *)strchr((char *)warning_data, ':');
	warning_data++;
	parsedBox = tlv_box_parse(warning_data, warning_data_len);
	if (parsedBox == NULL) {
		ret = -1;
		goto out;
	}

	if (tlv_box_get_bytes(parsedBox, BASELINE_WARNING_DATA, (unsigned char *)&baseline_warning_data, &baseline_warning_data_length) == 0) {
		tlv_box_get_uchar(parsedBox, APP_PROTO, &app_proto);
		handle_baseline_warning_data(app_proto, baseline_warning_data);
	} else {
		tlv_box_get_uchar(parsedBox, APP_PROTO, &app_proto);
		switch(app_proto) {
			case MODBUS:
				handle_warning_modbus_data(parsedBox);
				break;
			case DNP3:
				handle_warning_dnp3_data(parsedBox);
				break;
			case TRDP:
				handle_warning_trdp_data(parsedBox);
				break;
			case ENIP:
				handle_warning_enip_data(parsedBox);
				break;
			default:
				break;
		}
	}
out:
	if (parsedBox) {
		tlv_box_destroy(parsedBox);
	}
	return ret;
}

void *channel_reader(void *arg)
{
	redisContext *context = NULL;
	redisReply *reply = NULL;

	context = redisConnect(REDIS_SERVER_IP, REDIS_SERVER_PORT);
	if (context == NULL || (context!= NULL && context->err)) {
		printf("connect redis server error.\n");
		goto out;
	}
	while(1) {
		reply = redisCommand(context, "brpop audit study warning 0");
		if (reply) {
			switch(reply->type) {
				case REDIS_REPLY_ARRAY:
					if (reply->elements > 1) {
						if (!strncmp(reply->element[0]->str, "audit", strlen("audit"))) {
							for (int i = 1; i < reply->elements; i++)
								handle_audit_data(reply->element[i]->str);
						} else if (!strncmp(reply->element[0]->str, "study", strlen("study"))) {
							for (int i = 1; i < reply->elements; i++)
								handle_study_data(reply->element[i]->str);
						} else if (!strncmp(reply->element[0]->str, "warning", strlen("warning"))) {
							for (int i = 1; i < reply->elements; i++)
								handle_warning_data(reply->element[i]->str);
						}
					}
					break;
				default:
					break;
			}
		}
		freeReplyObject(reply);
	}
out:
	if (context)
		redisFree(context);
	return NULL;
}

int main(int argc, char **argv)
{
	int ret = SQL_SUCCESS;
	pthread_t redis_channel_thread_id;

	ret = sql_database_init();
	if (ret != SQL_SUCCESS) {
		printf("create mysql database error.\n");
		goto out;
	}
	ret = sql_tables_init(SQL_DB);
	if (ret != SQL_SUCCESS) {
		printf("create mysql tables error.\n");
		goto out;
	}
	if (pthread_create(&redis_channel_thread_id, NULL, channel_reader, NULL)) {
		printf("create pthread error.\n");
		goto out;
	}
	pthread_join(redis_channel_thread_id, NULL);
out:
	return 0;
}
