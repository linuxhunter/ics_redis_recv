#ifndef __REDIS_SUBSCRIPT_H
#define __REDIS_SUBSCRIPT_H

#define REDIS_SERVER_IP	"127.0.0.1"
#define REDIS_SERVER_PORT	6379
#define ICS_AUDIT_CHANNEL	"ChannelICSAudit"
#define ICS_STUDY_CHANNEL	"ChannelICSStudy"
#define ICS_WARN_CHANNEL	"ChannelICSWarn"

#define ETH_ADDR_STRING_LEN	19

#define TRDP_MIN_PD_HEADER_SIZE sizeof(TRDP_PD_Header_t)    /**< PD header size with FCS                */
#define TRDP_MAX_PD_DATA_SIZE   1432u       /**< PD data                                */
#define TRDP_MAX_PD_PACKET_SIZE (TRDP_MAX_PD_DATA_SIZE + TRDP_MIN_PD_HEADER_SIZE)
#define TRDP_MAX_MD_DATA_SIZE   65388u      /**< MD payload size                        */
#define TRDP_MAX_MD_PACKET_SIZE (TRDP_MAX_MD_DATA_SIZE + sizeof(MD_HEADER_T))

#define HTTP1_URI_SIZE		1024

typedef enum {
	MODBUS = 0,
	DNP3,
	TRDP,
	HTTP1,
	FTP,
	FTPDATA,
	TELNET,
	ICS_PROTO_MAX,
} ics_proto_t;

typedef enum {
	BEGIN = 1,
	TEMPLATE_ID,
	SRC_MAC,
	DST_MAC,
	SRC_IPv4,
	DST_IPv4,
	SRC_PORT,
	DST_PORT,
	PROTO,
	FLOW_HASH,
	PKTLEN,
	PAYLOAD_LEN,
	APP_PROTO,
	MODBUS_AUDIT_DATA,
	MODBUS_STUDY_DATA,
	MODBUS_WARNING_DATA,
	DNP3_AUDIT_DATA,
	DNP3_STUDY_DATA,
	DNP3_WARNING_DATA,
	TRDP_AUDIT_DATA,
	TRDP_STUDY_DATA,
	TRDP_WARNING_DATA,
	HTTP1_AUDIT_DATA,
	FTP_AUDIT_DATA,
	TELNET_AUDIT_DATA,
	END,
} ics_tlv_type_t;

typedef enum {
	FTP_COMMAND_LENGTH = 0x1000,
	FTP_COMMAND,
	FTP_PARAMS_LENGTH,
	FTP_PARAMS,
} ics_ftp_tlv_type_t;

typedef enum {
	TELNET_DATA_LENGTH = 0x2000,
	TELNET_DATA,
} ics_telnet_tlv_type_t;

typedef enum TRDP_Packet_Type_ {
    PD_PDU = 0,
    MD_PDU = 1,
} TRDP_Packet_Type_t;

typedef struct {
	int template_id;
	uint32_t sip;
	uint32_t dip;
	uint8_t proto;
} study_common_data_t;

typedef struct {
	study_common_data_t common;
	uint8_t funcode;
	uint8_t group;
	uint8_t variation;
	uint32_t index;
	uint32_t size;
} study_dnp3_data_t;

typedef struct {
	uint8_t smac[6];
	uint8_t dmac[6];
	uint32_t sip;
	uint32_t dip;
	uint16_t sp;
	uint16_t dp;
	uint8_t proto;
	uint32_t flow_hash;
	uint32_t pktlen;
	uint16_t payload_len;
} audit_common_data_t;

typedef struct {
	audit_common_data_t common;
	uint8_t funcode;
	uint32_t object_counts;
	int32_t object_length;
	uint8_t *objects;
} audit_dnp3_data_t;

typedef struct TRDP_PD_Header_ {
    uint32_t sequence_counter;              /**< Unique counter (autom incremented)                     */
    uint16_t protocol_version;              /**< fix value for compatibility (set by the API)           */
    uint16_t msg_type;                      /**< of datagram: PD Request (0x5072) or PD_MSG (0x5064)    */
    uint32_t com_id;                        /**< set by user: unique id                                 */
    uint32_t ebt_topo_cnt;                  /**< set by user: ETB to use, '0' for consist local traffic */
    uint32_t op_trn_topo_cnt;               /**< set by user: direction/side critical, '0' if ignored   */
    uint32_t dataset_length;                /**< length of the data to transmit 0...1432                */
    uint32_t reserved;                      /**< reserved for ServiceID/InstanceID support              */
    uint32_t reply_com_id;                  /**< used in PD request                                     */
    uint32_t reply_ip_address;              /**< used for PD request                                    */
    uint32_t frame_checksum;                /**< CRC32 of header                                        */
} TRDP_PD_Header_t;

typedef struct TRDP_MD_Header_ {
    uint32_t sequence_counter;              /**< Unique counter (autom incremented)                     */
    uint16_t protocol_version;              /**< fix value for compatibility (set by the API)           */
    uint16_t msg_type;                      /**< of datagram: PD Request (0x5072) or PD_MSG (0x5064)    */
    uint32_t com_id;                        /**< set by user: unique id                                 */
    uint32_t ebt_topo_cnt;                  /**< set by user: ETB to use, '0' for consist local traffic */
    uint32_t op_trn_topo_cnt;               /**< set by user: direction/side critical, '0' if ignored   */
    uint32_t dataset_length;                /**< length of the data to transmit 0...1432                */
    int32_t reply_status;                   /**< 0 = OK                                                 */
    uint8_t session_id[16u];                /**< UUID as a byte stream                                  */
    uint32_t reply_timeout;                 /**< in us                                                  */
    uint8_t source_uri[32u];                /**< User part of URI                                       */
    uint8_t destination_uri[32u];           /**< User part of URI                                       */
    uint32_t frame_checksum;                /**< CRC32 of header                                        */
} TRDP_MD_Header_t;

typedef struct TRDP_PD_PACKET_ {
    TRDP_PD_Header_t header;
    uint8_t data[TRDP_MAX_PD_DATA_SIZE];
} TRDP_PD_PACKET_t;

typedef struct TRDP_MD_PACKET_ {
    TRDP_MD_Header_t header;
    uint8_t data[TRDP_MAX_MD_DATA_SIZE];
} TRDP_MD_PACKET_t;

typedef struct TRDP_PACKET_ {
    TRDP_Packet_Type_t packet_type;;
    union {
        TRDP_PD_PACKET_t pd;
        TRDP_MD_PACKET_t md;
    }u;
} TRDP_PACKET_t;

typedef TRDP_PACKET_t ics_trdp_t;

#define MODBUS_DATA_LEN_MAX 64
typedef struct {
    uint8_t funcode;
    union {
        struct addr_quan {
            uint16_t address;
            uint16_t quantity;
        } addr_quan;
        struct addr_data {
            uint16_t address;
            uint16_t data;
        } addr_data;
        struct subfunc {
            uint16_t subfunction;
        } subfunc;
        struct addr_quan_data {
            uint16_t address;
            uint16_t quantity;
            uint8_t data_len;
            uint8_t data[MODBUS_DATA_LEN_MAX];
        } addr_quan_data;
        struct and_or_mask {
            uint16_t and_mask;
            uint16_t or_mask;
        } and_or_mask;
        struct rw_addr_quan {
            uint16_t read_address;
            uint16_t read_quantity;
            uint16_t write_address;
            uint16_t write_quantity;
        } rw_addr_quan;
    }u;
} ics_modbus_t;

typedef struct {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    uint8_t funcode;
    uint32_t address;
    uint32_t quantity;
} modbus_ht_item_t;

typedef struct {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    uint8_t funcode;
    uint8_t group;
    uint8_t variation;
    uint32_t index;
    uint32_t size;
} dnp3_ht_item_t;

typedef struct {
    uint32_t sip;
    uint32_t dip;
    uint8_t proto;
    TRDP_Packet_Type_t packet_type;
    uint16_t protocol_version;
    uint16_t msg_type;
    uint32_t com_id;
} trdp_ht_item_t;

typedef struct {
	audit_common_data_t common;
	char *http_uri;
	uint32_t http_uri_len;
} audit_http1_data_t;

typedef struct {
	audit_common_data_t common;
	char *command;
	uint8_t command_length;
	char *params;
	uint32_t params_length;
} audit_ftp_data_t;

typedef struct {
	audit_common_data_t common;
	int data_length;
	char *data;
} audit_telnet_data_t;

#endif
