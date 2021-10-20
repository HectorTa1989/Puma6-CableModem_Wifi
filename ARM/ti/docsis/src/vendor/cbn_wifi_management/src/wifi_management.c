#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include "docsis_db.h"
#include "cram_db.h"
#include "cbn_api_wificmd.h"
#include "wlan_config_api.h"
#include "wlan_rpc_client_api.h"
#include "cbn_factory_db.h"
#include "cbn_wifidb_all.h"

#define WIFI_BRING_UP_MONITOR_MAX_WAIT_TIME (20*60) /* in second - 20*60 = 1200 seconds = 20 minutes */

#if 0
	#define DEBUG_PRINT(fmt, args...) printf("DEBUG_PRINT: %s(%d): " fmt"\n", __func__, __LINE__, ##args); fflush(stdout)
#else
	#define DEBUG_PRINT(fmt, args...)
#endif

static CmMacParamsStatus_e get_cm_status(void)
{
	CmMacParams_t *cmp;
	CmMacParamsStatus_e macStatus = DOCSIS_CM_STAT_PARAMS_NOT_READY;

	if ((cmp = Cm_DocsisDb_GetCmMacParamsP()) == NULL)
	{
		printf("CBN:: %s(%d):: Cm_DocsisDb_GetCmMacParamsP failed\n", __func__, __LINE__);
	}
	else
	{
		macStatus = cmp->macStatus;
	}
	return macStatus;
}

static int init(void)
{
	if(DocsisParamsDb_RetrieveAccess() == STATUS_NOK)
	{
		printf("CBN:: %s(%d):: DocsisParamsDb_RetrieveAccess fail (in %s)\n", __func__, __LINE__, __FILE__);
		return -1;
	}

	if(CRamDb_RetrieveAccess() == STATUS_NOK)
	{
		printf("CBN:: %s(%d):: CRamDb_RetrieveAccess fail (in %s)\n", __func__, __LINE__, __FILE__);
		return -1;
	}

	if( CbnWiFiDb_All_RetrieveAccess() != OK )
	{
		printf("CBN:: %s(%d):: CbnWiFiDb_All_RetrieveAccess fail (in %s)\n", __func__, __LINE__, __FILE__);
		return -1;
	}

	int rpc_retry = 0;
	while (wlan_rpcConnectClient() != STATUS_OK)
	{
		rpc_retry++;
		printf("CBN:: %s(%d):: Failed to connect WLAN RPC Client (in %s)\n", __func__, __LINE__, __FILE__);

		if(rpc_retry >= 10)
		{
			return -1;
		}
		sleep(1);
	}
	return 0;
}
/* [Description]
For debug CH7465LG-1699, need to set /nvram/tftp_server at ARM side.
1. save the TI LOG which is enabled in logger.
2. save the result of ps an free command into log file every 5 min.
3. tftp the log file every 30 sec. 
*/
static int isFileExist(const char* filename)
{
    FILE* fp;

    if ((fp = fopen(filename, "r")) == NULL) {
        return 0;
    } else {
        fclose(fp);
        return 1;
    }
}

static void first_wifi_boot()
{
	struct sysinfo s_info;
	int error, rpc_retry = 0;
	long count = 0;
	CBN_WiFi_Permission_e wifi_permission = CBN_WIFI_PERMISSION_NOT_ALLOW_TO_BRING_UP;

	if(GetCRAMDB_wifiPermission(&wifi_permission) != STATUS_OK)
	{
		printf("CBN:: %s, %d, Failed to get the Wi-Fi permission status.\n", __func__, __LINE__);
	}

	if(wifi_permission == CBN_WIFI_PERMISSION_ALLOW_TO_BRING_UP)
	{
		while(wlan_rpcConnectClient() != STATUS_OK)
		{
			rpc_retry++;
			printf("CBN:: %s(%d):: RPC connect WiFi Failed (in %s)\n", __func__, __LINE__, __FILE__);
			sleep(1);
		}
		SetDot11ApplySettingCmd();
    
    // debug - [CH7465LG-1699]
	  char IfExecute[32] = "cat /var/run/tftp_log.pid";
	  if(!isFileExist(IfExecute))
	  {
		  char cmd[64] = {0};
		  snprintf(cmd, sizeof(cmd), "/usr/sbin/ARM_TFTP_UPLOAD.sh &");
		  system(cmd);
	  }
	  // debug - [CH7465LG-1699]
    DEBUG_PRINT("Times out!!!\n");
		return;
	}

	error = sysinfo(&s_info);

	// long wait_time = atoi(agrv[1]),
	// printf("wait_time=[%ld]\n", wait_time);


	if(error != 0)
	{
		s_info.uptime = 0;
	}
	count = s_info.uptime;

	DEBUG_PRINT("Uptime = %lds,  CM_Status=[%d]\n", s_info.uptime, get_cm_status());

	/* CH7465LG-723 adjust double loading of Wifi drivers during boot
		Request is to do the first time driver load with all SSIDs disabled (i.e. radio is off)
		A timer must be initiated so that if there is no DOCSIS connectivity detected for 20 minutes then the SSIDs can be broadcasted and the customer is able to connect.
		Once DOCSIS connectivity resumes the second driver load triggers and the customer will be kicked and have to reconnect.
	*/
	while(s_info.uptime < WIFI_BRING_UP_MONITOR_MAX_WAIT_TIME && count < WIFI_BRING_UP_MONITOR_MAX_WAIT_TIME && get_cm_status() != DOCSIS_CM_STAT_PARAMS_OPERATIONAL)
	{
		sleep(1);
		count++;

		error = sysinfo(&s_info);
		while(error != 0 && count < WIFI_BRING_UP_MONITOR_MAX_WAIT_TIME && get_cm_status() != DOCSIS_CM_STAT_PARAMS_OPERATIONAL)
		{
			sleep(1);
			count++;
			error = sysinfo(&s_info);
		}
		DEBUG_PRINT("Uptime = %lds,  CM_Status=[%d]\n", s_info.uptime, get_cm_status());
	}
	DEBUG_PRINT("Uptime = %lds,  CM_Status=[%d]\n", s_info.uptime, get_cm_status());

	SetCRAMDB_isWifiReseting(1);

	if(SetCRAMDB_wifiPermission(CBN_WIFI_PERMISSION_ALLOW_TO_BRING_UP) != STATUS_OK)
	{
		printf("CBN:: %s(%d):: Failed to set the Wi-Fi permission status to CBN_WIFI_PERMISSION_ALLOW_TO_BRING_UP (in %s)\n", __func__, __LINE__, __FILE__);
	}

	SetDot11ApplySettingCmd();

	DEBUG_PRINT("Times out!!!\n");

	return;
}

static CmMacParamsStatus_e pre_CmStatus = DOCSIS_CM_STAT_PARAMS_OPERATIONAL;
static wlan_config_return_code_e rpc_result = WLAN_STATUS_ERROR;

static void down_up_public_ssid()
{
	CmMacParamsStatus_e cur_CmStatus = get_cm_status();

	switch(cur_CmStatus)
	{
		case DOCSIS_CM_STAT_PARAMS_OPERATIONAL:
		{
			if(pre_CmStatus != DOCSIS_CM_STAT_PARAMS_OPERATIONAL)
			{
				pre_CmStatus = DOCSIS_CM_STAT_PARAMS_OPERATIONAL;
				DEBUG_PRINT("pre_CmStatus is DOCSIS_CM_STAT_PARAMS_OPERATIONAL!!!\n");
				/* Start up the Public SSID */
				rpc_result = wlan_setCfgCmd("(rm /tmp/shutdown_pub_ssid; /usr/sbin/CBN_Down_Up_Public_SSID.sh)&");
				DEBUG_PRINT("rpc_result is %s!!!\n", (rpc_result==WLAN_STATUS_OK)?"WLAN_STATUS_OK":"WLAN_STATUS_ERROR");
			}
			else
			{
				/* if the pre_CmStatus is Operational, check whether the RPC need to be sent again depends on previous rpc_result */
				if(rpc_result != WLAN_STATUS_OK)
				{
					DEBUG_PRINT("rpc_result is NOT OK, send the RPC again!!!\n");
					rpc_result = wlan_setCfgCmd("(rm /tmp/shutdown_pub_ssid; /usr/sbin/CBN_Down_Up_Public_SSID.sh)&");
					DEBUG_PRINT("rpc_result is %s!!!\n", (rpc_result==WLAN_STATUS_OK)?"WLAN_STATUS_OK":"WLAN_STATUS_ERROR");
				}
			}
			break;
		}

		/* refer to docsis_db.h for other case */
		default:
		{
			if(pre_CmStatus == DOCSIS_CM_STAT_PARAMS_OPERATIONAL)
			{
				pre_CmStatus = cur_CmStatus;
				DEBUG_PRINT("pre_CmStatus is %d!!!\n", pre_CmStatus);
				/* Shutdown the Public SSID */
				rpc_result = wlan_setCfgCmd("(touch /tmp/shutdown_pub_ssid; /usr/sbin/CBN_Down_Up_Public_SSID.sh)&");
				DEBUG_PRINT("rpc_result is %s!!!\n", (rpc_result==WLAN_STATUS_OK)?"WLAN_STATUS_OK":"WLAN_STATUS_ERROR");
			}
			else
			{
				/* if the pre_CmStatus is NOT Operational, check whether the RPC need to be sent again depends on previous rpc_result */
				if(rpc_result != WLAN_STATUS_OK)
				{
					DEBUG_PRINT("rpc_result is NOT OK, send the RPC again!!!\n");
					rpc_result = wlan_setCfgCmd("(touch /tmp/shutdown_pub_ssid; /usr/sbin/CBN_Down_Up_Public_SSID.sh)&");
					DEBUG_PRINT("rpc_result is %s!!!\n", (rpc_result==WLAN_STATUS_OK)?"WLAN_STATUS_OK":"WLAN_STATUS_ERROR");
				}
			}
			break;
		}
	}

	return;
}

static void main_loop()
{
	for(;;)
	{
		sleep(5);

		/* CH7465LG-767 Public ssid still broadcasting when RF is disconnected
			An SSID can be automatically disabled if the HGW does not have an operational DOCSIS IP connection. This function can be enabled or disabled for each SSID.
		*/
		down_up_public_ssid();
	}
}

int main(int argc, char *agrv[])
{
	if(init() != 0)
	{
		printf("CBN:: %s(%d):: Failed to inti. Exit! (in %s)\n", __func__, __LINE__, __FILE__);
		return -1;
	}

	first_wifi_boot();

	// start the main loop to manage the Wi-Fi interface
	main_loop();

	return 0;
}
