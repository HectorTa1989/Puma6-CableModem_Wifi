/****************************************************************************
 *
 *   MODULE:  logger_module.c
 *   PURPOSE: Supports logging of messages in the code
 *
 ****************************************************************************/
#include <sys/types.h>
#include <shmdb.h>
#include <icc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys_shmdb.h>
#include <sys_ptypes.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <getopt.h>
#include <autoconf.h>

#include "logger.h"
#include "logger_module.h"
#include "common_components_ctx.h"
#include "sys_ctx.h"
#include "common_components_shmdb.h"
#include "nvmapis.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#ifdef CONFIG_TI_PCD
#include "pcdapi.h"
#endif

/**** Internal Definitions ****/
#define LOGGER_MAX_FORMAT_TEXT 	LOGGER_MAX_MESSAGE_TEXT + 100
#define LOGGER_FORMAT_MASK 		0x00FFFFFF

#define SETSIG(sa, sig, fun)	sa.sa_handler = fun; \
				sa.sa_flags = SA_RESTART; \
				sigaction(sig, &sa, 0L);

/**** Global Variables ****/
ICC_context_t logger_icc_id;
static int logger_console = -1;

static Char *loggerOutput = NULL;
static Bool loggerNoFork = False;
static Int32 loggerPriority = 0;

logger_state_t *logger_state = NULL;
logger_configuration_t *logger_config = NULL;

static const char *logger_print_format[] =
{
    "0x%02X ",     /* LOGGER_HEX_BUFFER_FORMAT */
    "%03d ",        /* LOGGER_DEC_BUFFER_FORMAT */
    "%03o ",        /* LOGGER_OCT_BUFFER_FORMAT */
    NULL,          /* LOGGER_NULL_BUFFER_FORAMT */
};

static const Uint8 logger_print_format_size[] =
{
    5,
    4,
    4,
    0
};

static Char* message_to_be_print_global = NULL;
static Uint32 message_size_global = 0;

/**** Local functions definitions ****/
static Int32 build_log_msg_when_no_format(logger_content_log_t *log_msg,
										Char *message_to_be_print,
										Char *time_buf);
static void logger_print_list(Int32 file_fd, logger_config_option_e conf_op, const Char *names_list[],
							  logger_component_e component_id, Int32 shift);
static void logger_set_config_default_values( void );
static void logger_set_limit_default_values( void );

void logger_terminate( int sig );

Uint32 log_find_buffer_string_size(Uint32 buffer_size, logger_buffer_format_e buffer_print_option);
int log_build_buffer_string (Char *buffer_string,
							 Uint32 buffer_size, Uint8 *buffer,
							 logger_buffer_format_e buffer_print_option);

Int32 log_sent_udp_msg( Char *msg, Uint32 msg_len, Int32 port, Char *ip);

static void logger_write( int fd, const char *buf );
static void logger_printf( int fd, const char *format, ... );
static void logger_save_configuration( void );

#define LOGGER_WRITE_TO_FILE( fd, buf, len ) \
do\
{\
    int ret;\
\
    ret = write( fd, buf, len );\
\
    if ( ret >= 0 )\
    {\
         len -= ret;\
         buf += ret;\
    }\
    else if( errno != EAGAIN ) \
        break; \
\
    } while( len );


static void logger_printf( int fd, const char *format, ... )
{
    #define LOGGER_MAX_TEMP_BUFFER_SIZE     2048

    int len;
    va_list va;
    char buffer[ LOGGER_MAX_TEMP_BUFFER_SIZE ];
    char *buf = buffer;

	va_start(va, format);
	len = vsnprintf( buf, LOGGER_MAX_TEMP_BUFFER_SIZE-1, format, va);
	va_end(va);

    LOGGER_WRITE_TO_FILE( fd, buf, len );
}

static void logger_write( int fd, const char *buf )
{
    int len = strlen( buf );

    LOGGER_WRITE_TO_FILE( fd, buf, len );
}


/*******************************************************************
 * Function Name : logger_terminate
 *******************************************************************
 * Description					:  Terminates the logger module
 * Inputs						:  signal received by the OS
 * Return Value				:  None
 *******************************************************************/
void logger_terminate( int sig )
{
   if ( logger_console > 0 )
   {
        if( sig == SIGSEGV )
            logger_write( logger_console, "TI Logger: Received segmentation fault.\n" );

        logger_write( logger_console, "TI Logger: Terminating...\n" );

        /* Close console file */
        close( logger_console );
   }

   /* Free global buffer */
   if( message_to_be_print_global )
      free (message_to_be_print_global);

   exit(0);
}


/*******************************************************************
 * Function Name : logger_init
 *******************************************************************
 * Description					:  Initiates the logger module
 * Inputs						:  None
 * Return Value					:  0   -   Success, <0     -   Error
 *******************************************************************/
Int32 logger_init( Char *filename )
{
    Int32 ret_val;
#ifdef CONFIG_TI_NVM
    Uint16 loggerRecordSize; /* used by NVRAM */
    Char   Comp, File; /* used by NVRAM */
#endif
    ICC_limit_t logger_limit;
    struct sigaction sa;

    shm_init(TI_COMMON_COMPONENTS_DB_ID, 0, 0);
    logger_state = (logger_state_t *)shm_create(TI_COMMON_COMPONENTS_DB_ID, TI_COMMON_COMPONENTS_LOGGER, TI_COMMON_COMPONENTS_CHUNK_SIZE_LOGGER);

    if (!logger_state)
    {
        perror("TI Logger: Cannot access shared memory");
        exit(1);
    }

    logger_config = &(logger_state->logger_config);

    /* Clear the structure */
    memset(logger_state, 0, sizeof(logger_state_t));

    /* New fields, initialize to non valid values */
    logger_config->bytes_limit = 0xFFFFFFFF;
    logger_config->message_limit = 0xFFFFFFFF;
    logger_config->logger_user_defined_format = LOGGER_DEFAULT_DISPLAY;

    /* Disable debug printouts by default */
    memset( logger_config->logger_debug_filter, 0, sizeof( long long ) * LOGGER_MAX_COMPONENT_NUMBER );

#ifdef CONFIG_TI_NVM
    /* Read configuratrion from NVRAM */
    Comp = TI_COMPONENT_COMMON_COMPONENTS + '0';
    File = TI_COMMON_COMPONENTS_LOGGER + '0';

    /* Try to get the configuration */
    ret_val = NVM_get_directly(Comp, File, LOGGER_CONFIGURATION, sizeof(logger_configuration_t), &loggerRecordSize, logger_config, True);

    /** the first time we set logger configuration with default values **/
    if (ret_val == NVM_ValueNotFound || ret_val == NVM_LengthMismatched)
    {
        logger_set_config_default_values();
    }
    else
    {
        if ((ret_val != NVM_LengthMismatched) && (ret_val != NVM_OK)) /* We don't want to fail in case of NVRAM error, load defaults anyway... */
        {
            logger_set_config_default_values();
        }
    }
#else
    /* Load default configuration values in case NVRAM manager is not active */
    logger_set_config_default_values();
#endif

	//CBN160901 Zacks add for CH7465LG-151 Full log enabled/ KDG - (CPE-CH7466-389) Logging on CLI should be disabled by default S
	if((logger_config->LoggerDisableInitOnce==NULL)||(logger_config->LoggerDisableInitOnce==False)){
		
		//set CLI logger to all component disable
		logger_set_config_default_values();
		
		//set flag to True
		logger_config->LoggerDisableInitOnce = True;
	}else{
		//flag is True, do nothing
	}
	//CBN160901 Zacks add for CH7465LG-151 Full log enabled/ KDG - (CPE-CH7466-389) Logging on CLI should be disabled by default E
	
    /* Limitations to message queue. 0 = Unlimited */
    /*CBN_S: Andy (2014/09/18)*/
    //if ((logger_config->bytes_limit == 0xFFFFFFFF) || (logger_config->message_limit == 0xFFFFFFFF))
    /*CBN_E: Andy (2014/09/18)*/
    {
        logger_set_limit_default_values();
    }

    /* To retain backward compatibility with versions less than 3 */
    if (LOGGER_SAVED_RECORD_VERSION < 3)
    {
        /* This is taken from the old version, and not used anymore */
        typedef enum logger_old_pre_define_formats_e
        {
            LOGGER_OLD_NO_FORMAT_MATCH = 0,
            LOGGER_OLD_FORMAT_FULL_DISPALY_BIT,
            LOGGER_OLD_FORMAT_EMPTY_DISPALY_BIT,
            LOGGER_OLD_FORMAT_TIME_COMP_MOD_BIT,
            LOGGER_OLD_FORMAT_TIME_ONLY_BIT,
            LOGGER_OLD_FORMAT_COMP_MOD_ONLY_BIT,

        } logger_old_pre_define_formats_e;

        /* This is an old version - we need to maintain the logger format */
        switch (logger_config->logger_pre_define_format)
        {
            case  LOGGER_OLD_FORMAT_EMPTY_DISPALY_BIT:
                logger_config->logger_pre_define_format = LOGGER_SHORT_DISPLAY;
                break;

            case  LOGGER_OLD_FORMAT_TIME_COMP_MOD_BIT:
                logger_config->logger_pre_define_format = LOGGER_TIME_COMP_MOD_DISPLAY;
                break;

            case  LOGGER_OLD_FORMAT_TIME_ONLY_BIT:
                logger_config->logger_pre_define_format = (1 << (LOGGER_TIMESTAMP_BIT));
                break;

            case  LOGGER_OLD_FORMAT_FULL_DISPALY_BIT:
                logger_config->logger_pre_define_format = LOGGER_FULL_DISPALY;
                break;

            default:
                logger_config->logger_pre_define_format = LOGGER_DEFAULT_DISPLAY;
                break;
        }

        logger_config->logger_output_config = (logger_config->logger_output_config & ~LOGGER_FORMAT_MASK) | logger_config->logger_pre_define_format;
        logger_save_configuration();
    }
    else
    {
        logger_config->logger_pre_define_format = logger_config->logger_output_config & LOGGER_FORMAT_MASK;
    }


    /* Permanent enable / disable the logger */
    logger_state->enabled = logger_config->penabled & 1;

    logger_state->message_limit = logger_config->message_limit;
    logger_state->bytes_limit   = logger_config->bytes_limit;


    /* Init ICC */
    ret_val = ICC_init();
    if (ret_val < 0)
    {
        perror("TI Logger: Failed to init ICC");
        return ret_val;
    }

    /* Try to reuse an existing destination point */
    logger_icc_id = ICC_dest_of(LOGGER_MODULE);

    /* Create a new destination point only if it wasn't created already */
    if (logger_icc_id == ICC_CONTEXT_NONE)
    {
        ret_val = ICC_create_destination_point(&logger_icc_id);

        if (ret_val < 0)
        {
            perror("TI Logger: Failed to create ICC dest point");
            return ret_val;
        }

        ICC_set_owner(logger_icc_id, LOGGER_MODULE);
    }

    logger_limit.limit_bytes = logger_config->bytes_limit;
    logger_limit.limit_messages = logger_config->message_limit;

    /* Limit the amount of logs */
    ICC_message_limit(logger_icc_id, &logger_limit, NULL);

    /* Open output file to console */
    if (filename)
    {
        logger_console = open(filename, O_WRONLY | O_NONBLOCK | O_APPEND);
    }

    if (logger_console < 0)
    {
        logger_console = open("/dev/console", O_WRONLY | O_NONBLOCK | O_APPEND);
    }

    if (logger_console < 0)
    {
        perror("TI Logger: Failed to open /dev/console file");
        return -1;
    }

    /* Handle termination signals */
    SETSIG(sa, SIGTERM, logger_terminate);
    SETSIG(sa, SIGINT, logger_terminate);
    SETSIG(sa, SIGSEGV, logger_terminate);

    return 0;
}

/*******************************************************************
 * Function Name : logger_config_msg_received
 *******************************************************************
 * Description					:  Handles config msgs received.
 * Inputs						:  config_msg - The configuration msg
 * Return Value					:  None
 *******************************************************************/
void logger_config_msg_received(logger_content_configure_t * config_msg)
{
    logger_configuration_t *local_config = logger_config;
    Uint16 allSeverityBits = 0;
	/* Get from the configuration structure the bitmap that
	   should be updated according to the config option */
    switch(config_msg->logger_config_option)
	{
		case LOGGER_CONF_OP_COMPONENT:
			/* TI_COMPONENT_LAST indicates set/unset all componenets */
			if(config_msg->attribute_type == TI_COMPONENT_LAST)
			{
				if(config_msg->is_set)
					local_config->logger_component_filter = 0xFFFFFFFF;
				else
					local_config->logger_component_filter = 0;
			}
			else /* set/unset one given component --> get componenet bitmap */
			{
                if(config_msg->is_set)
                    local_config->logger_component_filter |= (1 << (config_msg->attribute_type));
                else
                    local_config->logger_component_filter &= ~(1 << (config_msg->attribute_type));
			}
			break;

         case LOGGER_CONF_OP_MODULE_DEBUG:
			if(config_msg->attribute_type == LOGGER_MAX_MODULE_NUMBER)
			{
				if(config_msg->is_set)
					local_config->logger_debug_filter[config_msg->component_id] = ~0;
				else
					local_config->logger_debug_filter[config_msg->component_id] = 0;
			}
			else /* set/unset one given module --> get module's bitmap */
			{
			     if(config_msg->is_set)
				     local_config->logger_debug_filter[config_msg->component_id]
				     |= (1LL << config_msg->attribute_type);
			     else
				     local_config->logger_debug_filter[config_msg->component_id]
				     &= ~(1LL << config_msg->attribute_type);
			}
              break;

		case LOGGER_CONF_OP_MODULE:
			/* set/unset all modules */
			if(config_msg->attribute_type == LOGGER_MAX_MODULE_NUMBER)
			{
				if(config_msg->is_set)
					local_config->logger_module_filter[config_msg->component_id] = ~0;
				else
					local_config->logger_module_filter[config_msg->component_id] = 0;
			}
			else /* set/unset one given module --> get module's bitmap */
			{
				if(config_msg->is_set)
					local_config->logger_module_filter[config_msg->component_id]
					|= (1LL << config_msg->attribute_type);
				else
					local_config->logger_module_filter[config_msg->component_id]
					&= ~(1LL << config_msg->attribute_type);
			}
            break;

        case LOGGER_CONF_OP_SEVERITY:
            //Only in case the "AllSeveritiesConfig" CLI command is used - we want to cahnge all bits [0-16]
            if (config_msg->attribute_type == LOGGER_ALL_SEVERITY_BITS)
                allSeverityBits = 1;
            
            if (config_msg->is_set)
            {
                local_config->logger_severity_config |= ((1 << config_msg->attribute_type) - allSeverityBits);
            }
            else
            {
                local_config->logger_severity_config &= ~((1 << config_msg->attribute_type) - allSeverityBits);
            }
			break;

		case LOGGER_CONF_OP_FORMAT:
            /* Check if this is a user defined request */
            if( config_msg->attribute_type == LOGGER_USER_DISPLAY )
            {
                if(config_msg->is_set)
                {
                    local_config->logger_user_defined_format = local_config->logger_pre_define_format;
                    break;
                }
                else
                {
                    local_config->logger_output_config = ( local_config->logger_output_config & ~LOGGER_FORMAT_MASK ) | local_config->logger_user_defined_format;
                }
            }
            else
            {

                if(!config_msg->is_set)
                {
                    local_config->logger_output_config &= ~( 1 << config_msg->attribute_type );

                }
                else if(config_msg->is_set==1)
                {
                    local_config->logger_output_config |= ( 1 << config_msg->attribute_type );
                }
                else
                {
                    local_config->logger_output_config = ( local_config->logger_output_config & ~LOGGER_FORMAT_MASK ) | config_msg->attribute_type;
                }
            }

            local_config->logger_pre_define_format = local_config->logger_output_config & LOGGER_FORMAT_MASK;

			break;

		case LOGGER_CONF_OP_TARGET:
            /*CBN_S - Abi - 20170330 - implement voice logger target*/
            if(config_msg->is_set)
            {
                local_config->logger_output_config |= (1 << (config_msg->attribute_type + 24));
                if(config_msg->attribute_type == LOGGER_LOG_FILE_TARGET)
                {
                    if(logger_config->filename[ 0 ])
                    {
                        time_t rawTime;
                        struct tm *timeInfo;
                        char acTimeStamp[50],acBuf[100];

                        time(&rawTime);
                        timeInfo = localtime(&rawTime);
                        strftime(acTimeStamp,sizeof(acTimeStamp),"%Y%m%d_%H%M%S_%p",timeInfo);
                        acTimeStamp[strlen(acTimeStamp)] = '\0';

                        sprintf(acBuf,"rm -rf %s",local_config->filename);
                        system(acBuf);

                        memset(acBuf,0,sizeof(acBuf));
                        sprintf(acBuf,"/var/tmp/logger_%s.txt",acTimeStamp);
                        strcpy(local_config->filename,acBuf);

                        memset(acBuf,0,sizeof(acBuf));
                        sprintf(acBuf,"echo > %s",local_config->filename);
                        system(acBuf);
                    }
                    local_config->logger_output_config &= ~(1 << (LOGGER_LOG_VOICE_FILE_TARGET + 24));
                }
            }
            else
            {
                local_config->logger_output_config &= ~(1 << (config_msg->attribute_type + 24));
            }
            /*CBN_E - Abi - 20170330 - implement voice logger target*/
            break;

		case LOGGER_CONF_OP_IP:
			strcpy(	local_config->logger_remote_target_ip,
					config_msg->ip_address);
			local_config->logger_remote_target_port = config_msg->port;
			break;

		case LOGGER_CONF_OP_FILENAME:
			strcpy(	local_config->filename,
					config_msg->filename);
			break;

		case LOGGER_CONF_OP_DEFAULT:
            logger_set_config_default_values();
			break;

        case LOGGER_CONF_OP_QUEUE_LIMIT_TEMPORARY:
        case LOGGER_CONF_OP_QUEUE_LIMIT:
        {
            ICC_limit_t logger_limit;

            logger_limit.limit_bytes = config_msg->bytes_limit;
            logger_limit.limit_messages = config_msg->message_limit;

            logger_state->bytes_limit = config_msg->bytes_limit;
            logger_state->message_limit = config_msg->message_limit;

            if (config_msg->logger_config_option == LOGGER_CONF_OP_QUEUE_LIMIT)
            {
                /* Limitations to message queue. 0 = Unlimited */
                local_config->bytes_limit = config_msg->bytes_limit;
                local_config->message_limit = config_msg->message_limit;
            }

            ICC_message_limit(logger_icc_id, &logger_limit, NULL);
            break;
        }

        case LOGGER_CONF_OP_STATE:
             {
                 if (config_msg->is_set)
                 {
                     local_config->penabled = ( LOGGER_RECORD_VERSION << 1 ) | 1;       
                 }
                 else 
                 {
                     local_config->penabled = ( LOGGER_RECORD_VERSION << 1 ); 
                 }
             }
            break;


         default:
			break;

	}

    logger_save_configuration();
}

static void logger_save_configuration( void )
{
#ifdef CONFIG_TI_NVM
	Char					Comp,File; //used by NVRAM
	Char					NVM_type[4];
	Uint16					loggerRecordSize;
    Int32					ret_val;

    /* Write configuratrion to NVRAM */
	Comp=TI_COMPONENT_COMMON_COMPONENTS + '0';
	File=TI_COMMON_COMPONENTS_LOGGER + '0';

    logger_config->penabled = ( logger_config->penabled & 1 ) | ( LOGGER_RECORD_VERSION << 1 );

	ret_val = NVM_set_directly(Comp,File,LOGGER_CONFIGURATION,sizeof(logger_configuration_t),&loggerRecordSize,logger_config,True);
	if (ret_val!=NVM_OK)
	{
		logger_write( logger_console, "TI Logger: Failed to set NVRAM" );
	}

	sprintf(NVM_type,"%c%c%d",Comp,File,LOGGER_CONFIGURATION);
	ret_val = NVM_commit(NVM_type);
	if (ret_val!=NVM_OK)
	{
		logger_write( logger_console, "TI Logger: Failed to set NVRAM" );
	}
#endif
}

/*******************************************************************
 * Function Name : logger_log_msg_received
 *******************************************************************
 * Description					:  Handles log msgs received.
 * Inputs						:  log_msg - The log msg
 * Return Value					:  None
 *******************************************************************/
void logger_log_msg_received(logger_content_log_t * log_msg)
{
    Char* message_to_be_print;
    Char* buffer_string = NULL;
    Int32 check_len = -1;
    Uint32 message_size;
    Uint32 buffer_string_size = 0;
    Int32 ret_val;
    Char *time_buf = NULL;
    struct timeval time;
    logger_configuration_t *local_config = logger_config;
    logger_plugin_t *logger_plugin_ptr;
    Char *message_buffer;
    Char *file_name;
    Uint32 message_buffer_size;
    FILE *fp;



    /* Ignore messages when the module name is not initialized */
    if( logger_module_names[log_msg->component] == NULL )
   	     return;

    /* dynamically allocate memory for message_to_be_print */
    message_size = log_msg->log_string_size + 200; /* following LOGGER_MAX_FORMAT_TEXT logic */

    /* Check if we already have enough room */
    if ( message_size > message_size_global )
    {
         /* We don't. Reallocate enough room */
         message_to_be_print_global = realloc( message_to_be_print_global, message_size );

         if ( !message_to_be_print_global )
         {
              /* Memory allocation failed */
              message_size_global = 0;
              return;
         }

         message_size_global = message_size;
    }

    message_to_be_print = message_to_be_print_global;

    if (log_msg->msg_type == LOGGER_LOG_MSG_FILE)
    {
        /* The message format is:
           log_msg->log_string + log_msg->log_string_size bytes is the actual string to print
           4 bytes = Uint32 the file size.
           other bytes = the file name
           */
        memcpy(&message_buffer_size, (log_msg->log_string + log_msg->log_string_size + 1), sizeof(Uint32));
        file_name = (Char *)(log_msg->log_string + log_msg->log_string_size + 1 + sizeof(Uint32));
        fp = fopen(file_name, "r");

        if (!fp)
        {
            printf("Error opening file %s\n", file_name);
            remove(file_name);
            return;
        }

        message_buffer = malloc(message_buffer_size);
        if (NULL == message_buffer)
        {
            printf("Failed to allocate memory for buffer\n");
            fclose(fp);
            remove(file_name);
            return;
        }

        fread(message_buffer, 1, message_buffer_size, fp);
        fclose(fp);
        /* Delete the file, we don't need it any more*/
        if (remove(file_name))
        {
            printf("Failed to remove file %s\n", file_name);
        }
    }
    else
    {
        message_buffer = log_msg->log_string + log_msg->log_string_size + 1;
        message_buffer_size = log_msg->buffer_size; 
    }

    /* Handling the buffer (if buffer exists -> buffer_size > 0) */
    if (message_buffer_size > 0)
    {
       if (log_msg->severity == LOGGER_SVR_PLUGIN_BUFFER)
       /* Check for existance of the plugin and if plugin exists execute it. */
       {
           if (logger_plugin_structure[log_msg->component] != NULL)
           {
               logger_plugin_ptr = &logger_plugin_structure[log_msg->component][log_msg->module];
               if (logger_plugin_ptr->logger_plugin_function != NULL)
               {
                   logger_plugin_ptr->logger_plugin_function(logger_plugin_ptr->logger_plugin_data_structure, &buffer_string, &buffer_string_size, message_buffer, message_buffer_size); 
               }
           }
       }
       else
       {
            /* find buffer string size */
           buffer_string_size = log_find_buffer_string_size(message_buffer_size, log_msg->buffer_print_option);
           if (buffer_string_size < 0)
           {
               goto freeBuffer;
           }
           /* allocate memory */
           buffer_string = malloc(buffer_string_size);
           if (buffer_string == NULL)
           {
               goto freeBuffer;
           }
           /* build buffer string */
           ret_val = log_build_buffer_string(	buffer_string,
                                                message_buffer_size,
                                                (Uint8 *)message_buffer,
                                                log_msg->buffer_print_option);

           if (ret_val < 0)
           {
                free(buffer_string);
                goto freeBuffer;
           }
       }
    }

    gettimeofday(&time, NULL);

    if( ( time_buf = ctime( &time.tv_sec ) ) != NULL )
         time_buf[ strlen( time_buf ) - 1 ] = ' ';

	/* build string according to configured format */
	switch (local_config->logger_pre_define_format)
	{
#ifdef CONFIG_TI_LOGGER_FUNCTION_LINE_DISPLAY_ENABLE
        case LOGGER_FULL_DISPALY:
			check_len=snprintf(message_to_be_print, message_size,
							   "%s[%s] [%s.%s(pid=%d)(%s:%d)]: %s\n",
							   time_buf,
							   logger_severity_names[log_msg->severity],
							   logger_component_names[log_msg->component],
							   logger_module_names[log_msg->component][log_msg->module],
							   log_msg->pid,
							   log_msg->function,
							   log_msg->line,
							   log_msg->log_string);
			break;
#endif
		case LOGGER_SHORT_DISPLAY:
			check_len=snprintf(message_to_be_print, message_size, "[%s]: %s\n",
								logger_severity_names[log_msg->severity],
								log_msg->log_string);
			break;

#ifndef CONFIG_TI_LOGGER_FUNCTION_LINE_DISPLAY_ENABLE
        case LOGGER_FULL_DISPALY:
#endif
		case LOGGER_TIME_COMP_MOD_DISPLAY:
			check_len=snprintf(message_to_be_print, message_size,
							   "%s[%s] [%s.%s(pid=%d)]: %s\n",
								time_buf,
								logger_severity_names[log_msg->severity],
								logger_component_names[log_msg->component],
								logger_module_names[log_msg->component][log_msg->module],
								log_msg->pid,
                               log_msg->log_string);
			break;

		case LOGGER_DEFAULT_DISPLAY:
			check_len=snprintf(message_to_be_print, message_size,
							   "[%s] [%s.%s(pid=%d)]: %s\n",
								logger_severity_names[log_msg->severity],
								logger_component_names[log_msg->component],
								logger_module_names[log_msg->component][log_msg->module],
								log_msg->pid,
                               log_msg->log_string);
			break;

        default:
			check_len = build_log_msg_when_no_format(log_msg, message_to_be_print, time_buf);
			break;
    }

	/* Do not print in case of error */
	if( check_len < 0 )
	{
		if (buffer_string)
			free(buffer_string);
		return;
	}
  
  // Debugging TFTP TI LOG every 30 seconds
  FILE * fp99 = fopen("/var/tmp/log_test","a+");
	if (fp99 != NULL)
	{
		fprintf(fp99, "%s", message_to_be_print);
		fclose(fp99);
		//rotateLogFiles("/var/tmp/log_test");
	}

	/* Send complete log message to enabled targets */
	if(local_config->logger_output_config & (1<<(LOGGER_STDIO_TARGET+24)))
	{
        if(message_to_be_print[check_len-2] == '\n')
        {
            /* Eliminate double new line */
            message_to_be_print[check_len-1] = '\0';
        }

        logger_write( logger_console, message_to_be_print);

        if (buffer_string)
		{
			logger_write( logger_console, "\n\n" );
            logger_write( logger_console, buffer_string );
		}
    }

    if(local_config->logger_output_config & (1<<(LOGGER_LOG_FILE_TARGET+24)))
    {
        Int32 file_fd = -1;

        if ( local_config->filename[ 0 ] )
        {
            file_fd = open(local_config->filename, O_WRONLY | O_APPEND | O_NONBLOCK );
        }
        
        if ( file_fd > 0 )
        {
            logger_write( file_fd, message_to_be_print);
        
            if (buffer_string)
            {
                logger_write( file_fd, "\n\n" );
                logger_write( file_fd, buffer_string );
            }
            
            close(file_fd);
        }
        else
        {
            /* Clear the flag in runtime. File does not exist */
            local_config->logger_output_config &= ~(1<<(LOGGER_LOG_FILE_TARGET+24));
        }
    }
    /*CBN_S - Abi - 20170330 - implement voice logger target*/
    else if((local_config->logger_output_config & (1<<(LOGGER_LOG_VOICE_FILE_TARGET+24))) && \
        ((log_msg->component == TI_COMPONENT_VOICE) || (log_msg->component == TI_COMPONENT_PACM)))
    {
        Int32 file_fd = -1;
        int size;
        struct stat st;
        stat(local_config->filename, &st);
        size = st.st_size;
        Bool bFlag = 1;

        if( size <= 20971520 /*20 MB*/){
            if ( local_config->filename[ 0 ] )
            {
                file_fd = open(local_config->filename, O_WRONLY | O_APPEND | O_NONBLOCK );
            }

            if ( file_fd > 0 ){
                logger_write( file_fd, message_to_be_print);

                if (buffer_string)
                {
                    logger_write( file_fd, "\n\n" );
                    logger_write( file_fd, buffer_string );
                }

                close(file_fd);
                bFlag = 0;
            }
        }

        if(bFlag){
            /* Clear the flag in runtime. File does not exist */
            local_config->logger_output_config &= ~(1<<(LOGGER_LOG_VOICE_FILE_TARGET+24));
        }
    }
    /*CBN_E - Abi - 20170330 - implement voice logger target*/

    if (local_config->logger_output_config & (1<<(LOGGER_UDP_TARGET+24)))
	{
		Uint32 msg_size = check_len + 1;
		/* send the message string */
		log_sent_udp_msg(	message_to_be_print,
							msg_size,
							local_config->logger_remote_target_port,
							local_config->logger_remote_target_ip );
		/* send the buffer string if exist */
		if (buffer_string)
		{
			log_sent_udp_msg(	buffer_string,
								buffer_string_size,
								local_config->logger_remote_target_port,
								local_config->logger_remote_target_ip );
		}
	}


	/* free buffer_string (if buffer exist) */
	if (buffer_string)
	{
		free(buffer_string);
	}

#ifdef CONFIG_TI_LOGGER_REBOOT_ON_FATAL
    /* Reboot the system, terminate init process */
    if ( log_msg->severity == LOGGER_SVR_FATAL )
    {
        kill( 1, SIGTERM );
    }
#endif

freeBuffer:
   if (log_msg->msg_type == LOGGER_LOG_MSG_FILE)
   {
       free(message_buffer);
   }
}

/*******************************************************************
 * Function Name : logger_print_list_msg_received
 *******************************************************************
 * Description					:  Handles print list msgs received.
 * Inputs						:  config_msg - The print list msg
 * Return Value					:  None
 *******************************************************************/
void logger_print_list_msg_received(logger_print_list_t * print_list_msg)
{
    Int32 file_fd = logger_console;

    if ( print_list_msg->temp_filename[ 0 ] )
    {
         file_fd = open(print_list_msg->temp_filename, O_WRONLY | O_APPEND | O_NONBLOCK );
         if(file_fd < 0)
         {
             file_fd = logger_console;
         }
    }

    /* Send the correct list to the 'logger_print_list()' function */
    switch(print_list_msg->conf_op)
	{
		case LOGGER_CONF_OP_COMPONENT:
			logger_write( file_fd, "\nLogger Components List:\n\n");
			logger_print_list(file_fd, LOGGER_CONF_OP_COMPONENT, logger_component_names, 0, 0);
            break;

         case LOGGER_CONF_OP_MODULE:
            if (print_list_msg->component_id == 0xFF)
            {
                Uint32 i;

                for( i = 0; i < TI_COMPONENT_LAST; i++)
                {
                    if( logger_component_names[i] == 0 )
                    {
                        break;
                    }

                    if( logger_module_names[i] == 0 )
                    {
                        continue;
                    }

                    logger_printf( file_fd, "\n----- Component: %s [ID=%d], Status: %s -----\n----- Modules List:\n\n", logger_component_names[i], i, (logger_config->logger_component_filter & (1 << i)) ? "Enabled " : "Disabled");
                    logger_print_list(file_fd, LOGGER_CONF_OP_MODULE, logger_module_names[i], i, 0); 
                }
            }
            else
            {
                if(( print_list_msg->component_id >= TI_COMPONENT_LAST ) || (logger_module_names[print_list_msg->component_id] == 0))
                {
                    logger_printf( file_fd, "Component id given (=%d) is invalid!\n",
                           print_list_msg->component_id);
                    return;
                }
                logger_printf( file_fd, "\n%s Modules List:\n\n",
                       logger_component_names[print_list_msg->component_id]);
                logger_print_list(file_fd, LOGGER_CONF_OP_MODULE,
                                  logger_module_names[print_list_msg->component_id],
                                  print_list_msg->component_id, 0);  
            }
			break;

		case LOGGER_CONF_OP_SEVERITY:
            logger_write( file_fd, "\n----- Logger Severities List:\n\n");
            logger_print_list(file_fd, LOGGER_CONF_OP_SEVERITY, logger_severity_names, 0, 0);
            if (print_list_msg->component_id < 0xFF)
            {
                break;
            }
        case LOGGER_CONF_OP_FORMAT:
            logger_write( file_fd, "\n----- Logger Display Format:\n\n");
            logger_print_list(file_fd, LOGGER_CONF_OP_FORMAT, logger_display_names, 0, 0);
            if (print_list_msg->component_id < 0xFF)
            {
                break;
            }
		case LOGGER_CONF_OP_TARGET:
			logger_write( file_fd, "\n----- Logger Targets List:\n\n");
			logger_print_list(file_fd, LOGGER_CONF_OP_TARGET, logger_target_names, 0, 24);
            if (print_list_msg->component_id < 0xFF)
            {
                break;
            }
		case LOGGER_CONF_OP_IP:
			logger_print_list(file_fd, LOGGER_CONF_OP_IP, logger_target_names, 0, 24);
            if (print_list_msg->component_id < 0xFF)
            {
                break;
            }
		case LOGGER_CONF_OP_FILENAME:
            logger_write( file_fd, "\n----- Logger output filename: " );
            if ( logger_config->filename[ 0 ] )
            {
               logger_printf( file_fd, "%s\n", logger_config->filename );
            }
            else
            {
               logger_write( file_fd, "None\n" );
            }
            if (print_list_msg->component_id < 0xFF)
            {
                break;
            }
       case LOGGER_CONF_OP_QUEUE_LIMIT:
            logger_write( file_fd, "\n----- Logger queue settings:\n" );
            logger_write( file_fd, "\n----- Permanent (NVRAM) settings:\n" );
            logger_printf( file_fd, "Logger queue length (0=unlimited): %d messages\n", logger_config->message_limit );
            logger_printf( file_fd, "Logger queue bytes length (0=unlimited): %d bytes\n", logger_config->bytes_limit );
            logger_write( file_fd, "\n----- Current settings:\n" );
            logger_printf( file_fd, "Logger queue length (0=unlimited): %d messages\n", logger_state->message_limit );
            logger_printf( file_fd, "Logger queue bytes length (0=unlimited): %d bytes\n", logger_state->bytes_limit );
            break;

       case LOGGER_CONF_OP_STATE:
            logger_write( file_fd, "\n----- Logger state is:\n\n" );
            logger_write( file_fd, "Temporary: ");
            /* print_list_msg->component_id is the logger temp state before entering the logger menu */ 
            if ( print_list_msg->component_id )
            {
               logger_write( file_fd, "enabled\n" );
            }
            else
            {
               logger_write( file_fd, "disabled\n" );
            }

            logger_write( file_fd, "Permanently: ");
            if ( (logger_config->penabled & 1) )
            {
               logger_write( file_fd, "enabled\n" );
            }
            else
            {
               logger_write( file_fd, "disabled\n" );
            }
            
            break;

        default:
            break;
    }

    if ( file_fd > 0 && file_fd != logger_console )
    {
        close( file_fd );
    }
}

/*******************************************************************
 * Function Name : logger_get_queue_limits_msg
 *******************************************************************
 * Description					:  Sets logger limits on input addtress.
 * Inputs						:  logger_get_configuration_t *logger_msg
 * Return Value					:  None
 *******************************************************************/ 

static void logger_get_queue_limits_msg( logger_get_configuration_t *logger_msg )
{ 
    ICC_message_t *icc_send_msg;
    Queue_Limits_t *logger_send_msg;
 
    /* Verify Valid Input */ 
    if ( (logger_msg == NULL) || (logger_msg->from < 0) )
    {
        return;
    }

    /* Allocate ICC message  */
    icc_send_msg = ICC_alloc_message(-1, sizeof(Queue_Limits_t), 0);
    if (icc_send_msg == NULL)
        return;
    logger_send_msg = ICC_data_ptr(icc_send_msg);  
 
    /* Prepare ICC message */
    logger_send_msg->message_limit = logger_config->message_limit;
    logger_send_msg->bytes_limit = logger_config->bytes_limit;

    /* Send ICC message */
    if ( ICC_send_message_head(logger_msg->from, icc_send_msg, 0) < 0 )
    {
        ICC_dispose_message(icc_send_msg);
    }
}


static void logger_main_usage( Char *execname )
{
    printf( "Usage: %s [options]\nOptions:\n\n", execname );
    printf( "-o FILE, --output=FILE\t\t\tOutput logs to a file (default /dev/console).\n" );
    printf( "-p [-20:19], --priority=[-20:19]\tSetup logger process priority (default 0).\n" );
    printf( "-n, --no-fork\t\t\t\tDo not fork.\n" );
    printf( "-h, --help\t\t\t\tPrint this message and exit.\n" );
    exit(0);
}

static void logger_parse_params( Int32 argc, Char *argv[] )
{
    opterr = 0;

    int c;

    while ( 1 )
    {
         struct option long_options[] =
         {
              /* These options set a flag. */
              {"no-fork", no_argument,       0, 'n'},
              {"help",    no_argument,       0, 'h'},
              {"output",  required_argument, 0, 'o'},
              {"priority",  required_argument, 0, 'p'},
              {0, 0, 0, 0}
         };

         /* getopt_long stores the option index here. */
         int option_index = 0;

         c = getopt_long( argc, argv, "nhop:", long_options, &option_index );

         /* Detect the end of the options. */
         if ( c == -1 )
              break;

         switch ( c )
         {
              case 0:
                   /* If this option set a flag, do nothing else now. */
                   if ( long_options[option_index].flag != 0 )
                        break;

              case 'n':
                   loggerNoFork = True;
                   break;

              case 'o':
                   loggerOutput = optarg;
                   break;

              case 'p':
                   loggerPriority = atoi(optarg);
                   if(( loggerPriority > 19 ) || ( loggerPriority < -20 ) )
                        loggerPriority = 0;
                   break;

              case 'h':
                   logger_main_usage( argv[ 0 ] );
                   break;

              case '?':
                   /* getopt_long already printed an error message. */
                   break;

              default:
                   abort( );
         }
    }
}

/*******************************************************************
 * Function Name : main
 *******************************************************************
 * Description					:  Initiaties the Logger module and
 *								   waites for messages.
 * Inputs						:  None
 * Return Value					:  0   -   Success, <0     -   Error
 *******************************************************************/
Int32 main( Int32 argc, Char *argv[] )
{
   Int32 ret_val;
   ICC_message_t *icc_msg;
   void *logger_msg;
   logger_msg_type_e *msg_type;
   pid_t child_pid;

#ifdef CONFIG_TI_PCD
   if( PCD_api_find_process_id(argv[0]) > 0 )
   {
       fprintf( stderr, "TI Logger: Another instance of the Logger is already active\n" );
       return 1;
   }
#endif

	/*CBN_S: Andy (2014/05/15)*/
	int fd_loggerconsole;
   	int fd_resetconsole;	
   	char redirectsessionpty[LOGGER_TERMINAL_MAX_SIZE];
   	logger_redirect_terminal_t *psessionterminal;
	/*CBN_E: Andy (2014/05/15)*/

   logger_parse_params( argc, argv );

   /* Initialize Module */
   ret_val = logger_init( loggerOutput );
   if( ret_val < 0 )
   {
       fprintf( stderr, "TI Logger: Failed to init the Logger\n" );
       return 1;
   }

   if ( loggerNoFork == False )
   {
       /* Spawn a child daemon and exit */
       if( (child_pid = fork()) != 0 )
       {
           if(child_pid == -1)
           {
               perror( "TI Logger: Failed to init the Logger" );
               exit(1);
           }

           /* Parent exiting... */
           exit(0);
       }
   }

   logger_attach_plugins();

   if(loggerPriority)
   {
       /* Setup the priority of the logger daemon */
       setpriority( PRIO_PROCESS, 0, loggerPriority );
   }

#ifdef CONFIG_TI_PCD
   PCD_api_send_process_ready();
   PCD_api_register_exception_handlers( argv[0], logger_terminate );
#endif
   logger_write( logger_console, "TI Logger: Init complete\n");

   /*CBN_S: Andy (2014/05/15)*/
   memset(redirectsessionpty, 0, sizeof(redirectsessionpty));
   /*CBN_E: Andy (2014/05/15)*/

   /* Child waits for logger messages */
   while( 1 )
   {
       ret_val = ICC_wait_message( logger_icc_id, &icc_msg, ICC_TIMEOUT_FOREVER );
       if ( ret_val < 0 )
           continue;

       logger_msg = ICC_data_ptr( icc_msg );

       /*CBN_S: Andy (2014/05/15)*/
       fd_loggerconsole = -1;
       fd_resetconsole = -1;
       if(strlen(redirectsessionpty)){
           fd_loggerconsole = open( redirectsessionpty,O_WRONLY | O_NONBLOCK | O_APPEND );
       }
       if(fd_loggerconsole != -1){
           fd_resetconsole = logger_console;
           logger_console = fd_loggerconsole;
       }
       /*CBN_E: Andy (2014/05/15)*/

       if( logger_msg )
       {
           msg_type = (logger_msg_type_e *) logger_msg;

           switch( *msg_type )
           {
               case LOGGER_CONFIGURATION_MSG:
                   logger_config_msg_received( (logger_content_configure_t *)logger_msg );
                   break;

               case LOGGER_LOG_MSG_FILE:
               case LOGGER_LOG_MSG:
                   logger_log_msg_received( (logger_content_log_t *)logger_msg );
                   break;

               case LOGGER_PRINT_LIST_MSG:
                   logger_print_list_msg_received( (logger_print_list_t *)logger_msg );
                   break;
           case LOGGER_GET_QUEUE_LIMITS_MSG:           
                   logger_get_queue_limits_msg( (logger_get_configuration_t *)logger_msg );
                   break;                

				/*CBN_S: Andy (2014/05/15)*/
				case LOGGER_REDIRECT_SESSION_PTY:
                   psessionterminal = (logger_redirect_terminal_t *) logger_msg;
                   if(psessionterminal->sessiontype == CBN_LOGGER_SESSION_PTY)
                   {
                       strcpy(redirectsessionpty, psessionterminal->loggerterminal);
                   }
				break;
				/*CBN_E: Andy (2014/05/15)*/

               default:
                   break;                   

		   }/* End Switch */
       }

		/*CBN_S: Andy (2014/05/15)*/
       if(fd_loggerconsole != -1){
			close(fd_loggerconsole);
           	if(fd_resetconsole != -1){
				logger_console = fd_resetconsole;
           	}
		}
       	/*CBN_E: Andy (2014/05/15)*/

       ICC_dispose_message( icc_msg );

   }/* End While */

   logger_terminate( 0 );
   return 0;
}


/******************************************************************************
 *  Local Functions
 ******************************************************************************/
/*******************************************************************
 * Function Name : build_log_msg_when_no_format
 *******************************************************************
 * Description					:  In case no pre-configured format is
 *									enable we need to check Format bitmap.
 * Inputs						:  log_msg - the message content
 *								:  max_message_size - the max size of the message
 * Output						:  message_to_be_print - the output text
 * Return Value					:  0   -   Success, <0     -   Error
 *******************************************************************/
static Int32 build_log_msg_when_no_format(logger_content_log_t *log_msg,
										Char *message_to_be_print,
										Char *time_buf)
{
    Uint32 idx = 0;

    /* checking if timestamp enable */
	if( (logger_config->logger_output_config & (1 << LOGGER_TIMESTAMP_BIT )) && time_buf )
    {
		idx += sprintf(message_to_be_print, time_buf);
    }

    /* Adding severity name */
    idx += sprintf(message_to_be_print+idx,"[%s]",logger_severity_names[log_msg->severity]);

    if( logger_config->logger_output_config & LOGGER_FULL_DISPALY )
    {
        strcat( message_to_be_print+idx," [" );
        idx+=2;

        /* checking if component enable */
        if (logger_config->logger_output_config & (1 << LOGGER_COMPONENET_BIT ))
        {
            idx += sprintf(message_to_be_print+idx,"%s", logger_component_names[log_msg->component] );

            if (logger_config->logger_output_config & (1 << LOGGER_MODULE_BIT ))
            {
                strcat( message_to_be_print+idx,"." );
                idx++;
            }
        }

        /* checking if module enable */
        if (logger_config->logger_output_config & (1 << LOGGER_MODULE_BIT ))
        {
            idx += sprintf(message_to_be_print+idx,"%s", logger_module_names[log_msg->component][log_msg->module]);
        }

        /* Insert process id to message */
        idx += sprintf(message_to_be_print+idx,"(pid=%d)", log_msg->pid );

#ifdef CONFIG_TI_LOGGER_FUNCTION_LINE_DISPLAY_ENABLE
        /* checking if function and line are enable */
        if (logger_config->logger_output_config & (1 << LOGGER_FUNCTION_LINE_NUM_BIT ))
        {
            idx += sprintf(message_to_be_print+idx,"(%s:%d)", log_msg->function,log_msg->line);
        }
#endif
        strcat( message_to_be_print+idx, "]" );
        idx++;
    }

    /* append ":" to "message_to_be_print" and the log itself */
    idx += sprintf(message_to_be_print+idx,": %s\n", log_msg->log_string);

	return idx;
}

/******************************************************************************
 * Function Name : logger_print_list
 *******************************************************************************
 * Description					:  Print a given list and indicates set/unset
 *									for each element in the list.
 * Inputs						:  conf_op  - type of list to print.
 *								   names_list - the list's names.
 *								   shift - used for chekcing the bitmaps.
 * Return Value					:  None
 ******************************************************************************/
static void logger_print_list(Int32 file_fd, logger_config_option_e conf_op, const Char *names_list[],
							  logger_component_e component_id, Int32 shift)
{
	Int32 i = 0, j = 0;
	long bitmap = 0;

	switch(conf_op)
	{
		case LOGGER_CONF_OP_COMPONENT:
			while(names_list[i] != 0)
			{
				if(logger_module_names[i] != 0)
				{
					logger_printf( file_fd, "[%2d] %s:%s%s", i, names_list[i], strlen(names_list[i]) >= 8 ? "\t":"\t\t",
						   (logger_config->logger_component_filter & (1 << i)) ? "Enabled " : "Disabled");

                    if( j & 1)
                    {
                        logger_write( file_fd, "\n" );
                    }
                    else
                    {
                        logger_write( file_fd, " |\t" );
                    }
                    j++;
                }

                i++;
			}

            if(j & 1 )
                logger_write( file_fd, "\n" );

            return;

		case LOGGER_CONF_OP_MODULE:
			while(names_list[i] != 0)
			{
				logger_printf( file_fd, "[%2d] %s%s%s%s", i, names_list[i],
                       (logger_config->logger_debug_filter[component_id] & (1LL << i)) ? "[DBG]:" : ":     ",
                       strlen(names_list[i]) >= 5 ? strlen(names_list[i]) > 12 ? "" : "\t" :"\t\t",
					   (logger_config->logger_module_filter[component_id] & (1LL << i)) ? "Enabled " : "Disabled");

                if( i & 1)
                {
                    logger_write( file_fd, "\n" );
                }
                else
                {
                    logger_write( file_fd, " |\t" );
                }

                i++;
			}
            if(i & 1 )
                logger_write( file_fd, "\n" );
            return;
		case LOGGER_CONF_OP_SEVERITY:
            bitmap = logger_config->logger_severity_config;
			break;
        case LOGGER_CONF_OP_FORMAT:
            bitmap = logger_config->logger_output_config;
            break;
		case LOGGER_CONF_OP_TARGET:
			bitmap = logger_config->logger_output_config;
			break;
		case LOGGER_CONF_OP_IP:
			logger_printf( file_fd,"\n----- UDP Target Settings:\n\nDestination IP: %s\nDestination Port: %d\n",logger_config->logger_remote_target_ip,logger_config->logger_remote_target_port);
			return;
		default:
			break;
	}

	while(names_list[i] != 0)
	{
		logger_printf( file_fd, "[%2d] %s:%s%s", i, names_list[i], strlen(names_list[i]) >= 8 ? "\t":"\t\t",
			   (bitmap & (1 << (i+shift))) ? "Enabled " : "Disabled");

        if( i & 1)
        {
            logger_write( file_fd, "\n" );
        }
        else
        {
            logger_write( file_fd, " |\t" );
        }

        i++;
	}

    if(i & 1 )
        logger_write( file_fd, "\n" );
}

/******************************************************************************
 * Function Name : logger_set_limit_default_values
 *******************************************************************************
 * Description					:  Set default values to the limitations.
 * Inputs						:  None
 * Return Value					:  None
 ******************************************************************************/
static void logger_set_limit_default_values( void )
{
   /* Limitations to message queue. 0 = Unlimited */
   	/*CBN_S: Andy (2014/09/18)*/
    /* set default values (unlimited) for logger bytes/messages */
#if 0   
   logger_config->bytes_limit = CONFIG_TI_LOGGER_BYTES_LIMIT;
   logger_config->message_limit = CONFIG_TI_LOGGER_MESSAGE_LIMIT;
#endif
	logger_config->bytes_limit = 0;
	logger_config->message_limit = 0;
	/*CBN_E: Andy (2014/09/18)*/
}

/******************************************************************************
 * Function Name : logger_set_config_default_values
 *******************************************************************************
 * Description					:  Set default values to the configuration.
 * Inputs						:  None
 * Return Value					:  None
 ******************************************************************************/
static void logger_set_config_default_values( void )
{
	Int32 i;
    logger_configuration_t *local_config = logger_config;

	strcpy(local_config->logger_remote_target_ip,CONFIG_TI_LOGGER_DESTINATION_IP);
    strcpy(local_config->filename, CONFIG_TI_LOGGER_FILENAME);

	local_config->logger_remote_target_port = CONFIG_TI_LOGGER_DESTINATION_PORT;
    //local_config->logger_component_filter = ~0;  //old code
	local_config->logger_component_filter = 0;  //CBN160901 Zacks for Disable all component
	
	for(i = 0; i < LOGGER_MAX_COMPONENT_NUMBER; i++)
	{
        local_config->logger_module_filter[i] = ~0;
    }
	local_config->logger_output_config = (1<<(LOGGER_STDIO_TARGET+24)) | LOGGER_DEFAULT_DISPLAY;
#ifdef CONFIG_TI_LOGGER_DEBUG_ENABLE /* Debug is enabled */
	local_config->logger_severity_config = 0x0000FFFF;
#else
	local_config->logger_severity_config = 0x0000BDFF;
#endif
	local_config->logger_pre_define_format = LOGGER_DEFAULT_DISPLAY;

    /* Disabled debug by default */
    memset( local_config->logger_debug_filter, 0, sizeof( long long ) * LOGGER_MAX_COMPONENT_NUMBER );

    /* Logger enabled + logger version */
    local_config->penabled = ( LOGGER_RECORD_VERSION << 1 ) | 1;
    logger_set_limit_default_values();

    logger_save_configuration();
}

/******************************************************************************
 * Function Name : log_find_buffer_string_size
 *******************************************************************************
 * Description					:  Get the buffer string size.
 * Inputs						:  buffer_size - the size of the array the buffer contains.
 *								:  buffer_print_option - HEX, DEC, etc.
 *
 *
 * Return Value					:  length of the string  -   Success, <0     -   Error
 ******************************************************************************/
Uint32 log_find_buffer_string_size(Uint32 buffer_size, logger_buffer_format_e buffer_print_option)
{
	Uint32 max_len_per_elem;
	Uint32 buffer_string_size;

    if( buffer_print_option < LOGGER_NULL_BUFFER_FORAMT )
        max_len_per_elem = logger_print_format_size[ buffer_print_option ];
    else
         return -1;

	buffer_string_size =	1 /*tab*/ +
							buffer_size * max_len_per_elem +
						(buffer_size/8) * 2 /* enter_and_tab */ +
						2 /* end_null */;

	return buffer_string_size;
}

/******************************************************************************
 * Function Name : log_build_buffer_string
 *******************************************************************************
 * Description					:  Build buffer string according to the buffer array and print option.
 * Inputs						:  buffer_string  -  the destination to which the string will be copied.
 *								:  buffer_size - the size of the buffer (number of elements inside the array).
 * 								:  buffer - an array of Uint8 elements.
 *								:  buffer_print_option - the format the buffer should be printed (HEX, DEC etc)
 * Return Value					:  length of the string  -   Success, <0     -   Error
 ******************************************************************************/
int log_build_buffer_string (Char *buffer_string,
							 Uint32 buffer_size, Uint8 *buffer,
							 logger_buffer_format_e buffer_print_option)
{
	int i;
	int ret_val;
	int buffer_string_index=0;
	const Char *print_format;

    if( buffer_print_option < LOGGER_NULL_BUFFER_FORAMT )
        print_format = logger_print_format[ buffer_print_option ];
    else
        return -1;

	buffer_string[buffer_string_index++] = '\t';
	for (i=0;i<buffer_size;i++)
	{
		ret_val = sprintf(buffer_string + buffer_string_index,print_format,buffer[i]);
		if (ret_val<0)
		{
			return -1;
		}
		buffer_string_index = buffer_string_index + ret_val;
		if( (!((i+1)%8)) && (i!=0) )
		{
			buffer_string[buffer_string_index++] = '\n';
			buffer_string[buffer_string_index++] = '\t';
		}
	}

	buffer_string[buffer_string_index++] = '\n';
	buffer_string[buffer_string_index++] = '\0';
	return buffer_string_index;
}

/******************************************************************************
 * Function Name : log_sent_udp_msg
 *******************************************************************************
 * Description					:  Send the log message through a UDP datagram
 * Inputs						:  msg -
 *								:  msg_len -
 * 								:  port -
 *								:  ip -
 * Return Value					:  length of the string  -   Success, <0     -   Error
 ******************************************************************************/
Int32 log_sent_udp_msg( Char *msg, Uint32 msg_len, Int32 port, Char *ip)
{
	Int32 sockfd;
	struct sockaddr_in their_addr; // connector's address information
	Int32 numbytes;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		return -1;
	}
	their_addr.sin_family = AF_INET;
	their_addr.sin_port = htons(port);
	their_addr.sin_addr.s_addr = inet_addr(ip);
	memset(their_addr.sin_zero, '\0', sizeof their_addr.sin_zero);
	if ((numbytes = sendto(sockfd, msg, msg_len, 0,(struct sockaddr *)&their_addr, sizeof their_addr)) == -1)
	{
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return numbytes;
}
