// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Realtek, Inc. */
/* Copyright (c) 2023-2024, msinwu <msinwu@realtek.com> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rpcundone.h"
#include "rpcundone.skel.h"
#include "trace_helpers.h"
#include "argparse.h"

#define __unused __attribute__((unused))

static struct env {
	bool fulldisplay;
	bool timestamp;
	bool noclear;
	bool verbose;
} env = {
	.fulldisplay = false,
	.timestamp = false,
	.noclear = false,
	.verbose = false,
};

static const char *const usages[] = {
	"rpcundone [-h] [-f] [-T] [-C] [-v]",
	NULL,
};

static const char doc[] =
"Trace Realtek remote procedure call undone.\n"
"\n"
"EXAMPLES:\n"
"    ./rpcundone           # trace Realtek remote procedure call undone\n"
"    ./rpcundone -C        # don't clear the screen\n"
"    ./rpcundone -f        # also display versionID, parameterSize, mycontext\n";

static struct argparse_option options[] = {
	OPT_HELP(),
	OPT_BOOLEAN('f', "fulldisplay", &env.fulldisplay, "Also display versionID, parameterSize, mycontext", NULL, 0, 0),
	OPT_BOOLEAN('T', "timestamp", &env.timestamp, "Include timestamp on output", NULL, 0, 0),
	OPT_BOOLEAN('C', "noclear", &env.noclear, "Don't clear the screen", NULL, 0, 0),
	OPT_BOOLEAN('v', "verbose", &env.verbose, "Verbose debug output", NULL, 0, 0),
	OPT_END(),
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

struct id_name {
	int id;
	const char *name;
};

static const char *map_lookup(struct id_name *map, int map_size, int id)
{
	for (int i = 0; i < map_size / sizeof(struct id_name); i++) {
		if (map[i].id == id)
			return map[i].name;
	}
	return NULL;
}

#define RPC_PG_ID_D_PROGRAM 97
#define RPC_PG_ID_R_PROGRAM 98
#define RPC_PG_ID_REPLYID 99
#define RPC_PG_ID_AUDIO_SYSTEM 201
#define RPC_PG_ID_AUDIO_AGENT 202
#define RPC_PG_ID_VIDEO_AGENT 300
#define RPC_PG_ID_VENC_AGENT 400
#define RPC_PG_ID_HIFI_AGENT 500

static struct id_name programID_to_name[] = {
	{RPC_PG_ID_D_PROGRAM, "D_PROGRAM"},
	{RPC_PG_ID_R_PROGRAM, "R_PROGRAM"},
	{RPC_PG_ID_REPLYID, "REPLYID"},
	{RPC_PG_ID_AUDIO_SYSTEM, "AUDIO_SYSTEM"},
	{RPC_PG_ID_AUDIO_AGENT, "AUDIO_AGENT"},
	{RPC_PG_ID_VIDEO_AGENT, "VIDEO_AGENT"},
	{RPC_PG_ID_VENC_AGENT, "VENC_AGENT"},
	{RPC_PG_ID_HIFI_AGENT, "HIFI_AGENT"},
};

static const char *programID_name(__u32 programID)
{
	const char *name = map_lookup(programID_to_name, sizeof(programID_to_name), programID);
	if (name)
		return name;
	static char buf[10];
	snprintf(buf, sizeof(buf), "%d", programID);
	return buf;
}

static struct id_name procedureID_a_agent2system[] = {
	{1, "AUDIO_RPC_ToSystem_ErrorStatus"}, {2, "AUDIO_RPC_ToSystem_DeliverFlush"},
	{3, "AUDIO_RPC_ToSystem_EndOfStream"}, {11, "AUDIO_RPC_ToSystem_ENC_GeneralInfo"},
	{12, "AUDIO_RPC_ToSystem_ENC_FrameInfo"}, {13, "AUDIO_RPC_ToSystem_ENC_EndOfStream"},
	{21, "AUDIO_RPC_ToSystem_DEC_GeneralInfo"}, {22, "AUDIO_RPC_ToSystem_DEC_FrameInfo"},
	{31, "AUDIO_RPC_ToSystem_AO_KaraokeModeIndicate"}, {32, "AUDIO_RPC_ToSystem_AO_ReportSPDIFStatus"},
	{33, "AUDIO_RPC_ToSystem_AO_PostMastership"}, {34, "AUDIO_RPC_ToSystem_AO_ConfigDACDone"},
	{40, "AUDIO_RPC_ToSystem_DAC_HardwareMute"}, {41, "AUDIO_RPC_ToSystem_ADC_HardwareMute"},
	{42, "AUDIO_RPC_ToSystem_HashCheck"}, {49, "AUDIO_RPC_ToSystem_HDMI_Mute"},
	{50, "AUDIO_RPC_ToSystem_HDMI_Setting"}, {51, "AUDIO_RPC_ToSystem_AudioHaltDone"},
	{52, "AUDIO_RPC_ToSystem_PrivateInfo"}, {53, "AUDIO_RPC_ToSystem_ARMFW_PrivateInfo"},
	{61, "VIDEO_RPC_ToSystem_EndOfStream"}, {68, "VIDEO_RPC_ToSystem_DVControlPathService"},
	{69, "VIDEO_RPC_ToSystem_PrivateInfo"}, {70, "VIDEO_RPC_ToSystem_OutputControl_Notify"}
};

static struct id_name procedureID_v_agent2system[] = {
	{5, "VIDEO_RPC_JPEG_ToSystem_EndOfDecSeg"}, {63, "VIDEO_RPC_DEC_ToSystem_FatalError"},
	{65, "VIDEO_RPC_ToSystem_VideoHaltDone"}, {67, "VIDEO_RPC_ToSystem_DecoderMessage"},
	{1018, "VIDEO_RPC_DEC_ToSystem_Deliver_FrameInfo"}, {1019, "VIDEO_RPC_DEC_ToSystem_Deliver_PicInfo"},
	{1020, "VIDEO_RPC_DEC_ToSystem_Deliver_MediaInfo"}, {1021, "VIDEO_RPC_ToSystem_VoutMessage"}
};

static struct id_name procedureID_a_system2agent[] = {
	{1, "AUDIO_RPC_ToAgent_Create"}, {2, "AUDIO_RPC_ToAgent_Connect"},
	{3, "AUDIO_RPC_ToAgent_InitRingBufferHeader"}, {4, "AUDIO_RPC_ToAgent_Run"},
	{5, "AUDIO_RPC_ToAgent_Pause"}, {6, "AUDIO_RPC_ToAgent_Stop"},
	{7, "AUDIO_RPC_ToAgent_Destroy"}, {8, "AUDIO_RPC_ToAgent_Flush"},
	{9, "AUDIO_RPC_ToAgent_SetRefClock"}, {10, "AUDIO_RPC_ToAgent_GetStatus"},
	{11, "AUDIO_RPC_ToAgent_SetSeeking"}, {12, "AUDIO_RPC_ToAgent_InitRingBufferHeaderExt"},
	{15, "AUDIO_RPC_ToAgent_BitstreamValidation"}, {16, "AUDIO_RPC_ToAgent_AudioConfig"},
	{31, "AUDIO_RPC_DEC_ToAgent_Init"}, {32, "AUDIO_RPC_DEC_ToAgent_SkipMode"},
	{51, "AUDIO_RPC_ENC_ToAgent_Init"}, {52, "AUDIO_RPC_ENC_ToAgent_SetBitRate"},
	{53, "AUDIO_RPC_ENC_ToAgent_StartEncoder"}, {54, "AUDIO_RPC_ENC_ToAgent_PauseEncoder"},
	{55, "AUDIO_RPC_ENC_ToAgent_StopEncoder"}, {56, "AUDIO_RPC_ENC_ToAgent_SetSourceFile"},
	{57, "AUDIO_RPC_ENC_ToAgent_Command"}, {58, "AUDIO_RPC_ENC_ToAgent_MuteEncoder"},
	{59, "AUDIO_RPC_ENC_SetEncoder"}, {60, "AUDIO_RPC_ENC_ToAgent_SetDVMixer"},
	{61, "AUDIO_RPC_ENC_ToAgent_SetNonRealTime"}, {81, "AUDIO_RPC_AO_ToAgent_Init"},
	{82, "AUDIO_RPC_AO_ToAgent_SetEaqualizer"}, {83, "AUDIO_RPC_AO_ToAgent_ConfigDelayControl"},
	{84, "AUDIO_RPC_AO_ToAgent_ConfigKaraoke"}, {85, "AUDIO_RPC_AO_ToAgent_ConfigMixer"},
	{86, "AUDIO_RPC_AO_ToAgent_ConfigPP"}, {87, "AUDIO_RPC_AO_ToAgent_Mute"},
	{88, "AUDIO_RPC_AO_ToAgent_ConfigDAC"}, {89, "AUDIO_RPC_AO_ToAgent_ConfigPrologic"},
	{110, "AUDIO_RPC_ToAgent_ADC0_Config"}, {111, "AUDIO_RPC_ToAgent_ADC1_Config"},
	{112, "AUDIO_RPC_ToAgent_SPDIF_Config"}, {113, "AUDIO_RPC_ToAgent_AI_BackDoor_Init"},
	{114, "AUDIO_RPC_ToAgent_SPDIF_Err_Threshold_Config"}, {115, "AUDIO_RPC_ToAgent_AIN_Switch_Focus"},
	{116, "AUDIO_RPC_ToAgent_AOUT_Copy_Source"}, {117, "AUDIO_RPC_ToAgent_AOUT_Volume_Control"},
	{118, "AUDIO_RPC_ToAgent_AOUT_SPDIF_Source"}, {119, "AUDIO_RPC_ToAgent_Karaoke_Control"},
	{120, "AUDIO_RPC_ToAgent_AIN_Mute"}, {121, "AUDIO_RPC_ToAgent_AOUT_Drop_Sample"},
	{122, "AUDIO_RPC_ToAgent_AOUT_Pink_White_Noise"}, {123, "AUDIO_RPC_ToAgent_AOUT_Send_Spectrum_Data"},
	{125, "AUDIO_RPC_ToAgent_PlaySoundEvent"}, {126, "AUDIO_RPC_ToAgent_AOUT_ResetPin"},
	{127, "AUDIO_RPC_ToAgent_AFC_Config"}, {128, "AUDIO_RPC_ToAgent_Audistry_Config"},
	{129, "AUDIO_RPC_ToAgent_HDMI_Mute"}, {130, "AUDIO_RPC_ToAgent_ADC2_Config"},
	{131, "AUDIO_RPC_ToAgent_AOUT_HDMI_Set"}, {132, "AUDIO_RPC_ToAgent_AO_Only_Switchfocus"},
	{133, "AUDIO_RPC_ToAgent_AIN_Data_Measurement"}, {134, "AUDIO_RPC_ToAgent_SET_CHANNEL_OUT_SWAP"},
	{200, "AUDIO_RPC_ToAgent_HDMI_OUT_EDID"}, {201, "AUDIO_RPC_ToAgent_HDMI_INFO"},
	{203, "AUDIO_RPC_ToAgent_UpdatePTS"}, {204, "AUDIO_RPC_ToAgent_EndOfStream"},
	{205, "AUDIO_RPC_ToAgent_SwitchFocus"}, {206, "AUDIO_RPC_ToAgent_DAC_I2S_Config"},
	{207, "AUDIO_RPC_ToAgent_DAC_SPDIF_Config"}, {208, "AUDIO_RPC_ToAgent_HDMI_OUT_VSDB"},
	{209, "AUDIO_RPC_ToAgent_HDMI_OUT_EDID2"}, {212, "AUDIO_RPC_ToAgent_DecoderConfig"},
	{213, "AUDIO_RPC_ToAgent_NightMode"}, {214, "AUDIO_RPC_ToAgent_PP_InitPin"},
	{228, "AUDIO_RPC_ToAgent_TrueHD_LosslessMode"}, {215, "AUDIO_RPC_ToAgent_AskDebugMemoryAddress"},
	{216, "AUDIO_RPC_ToAgent_PP_Config"}, {217, "AUDIO_RPC_ToAgent_PP_SRC_Config"},
	{218, "AUDIO_RPC_ToAgent_PP_PL2_Config"}, {219, "AUDIO_RPC_ToAgent_PP_MIXER_Config"},
	{220, "AUDIO_RPC_ToAgent_PP_BASS_MANAGEMENT_Config"}, {221, "AUDIO_RPC_ToAgent_PP_KEY_SHIFT_Config"},
	{222, "AUDIO_RPC_ToAgent_PP_REVERB_Config"}, {223, "AUDIO_RPC_ToAgent_PP_COMFORT_LISTEN"},
	{224, "AUDIO_RPC_ToAgent_PP_EQ_Config"}, {225, "AUDIO_RPC_ToAgent_PP_VOCAL_REMOVER_Config"},
	{226, "AUDIO_RPC_DEC_ToAgent_GetAudioFormatInfo"}, {227, "AUDIO_RPC_ToAgent_PP_DVS_Config"},
	{229, "AUDIO_RPC_ToAgent_Karaoke_Scoring"}, {230, "AUDIO_RPC_ToAgent_DEC_SetCodecKey"},
	{231, "AUDIO_RPC_ToAgent_PP_PTS_MIXER_Config"}, {232, "AUDIO_RPC_ToAgent_PP_FAKE_PTS_MIXER_Config"},
	{250, "AUDIO_RPC_ToAgent_Capability_SetMask"}, {251, "AUDIO_RPC_ToAgent_AudioHalt"},
	{252, "AUDIO_RPC_ToAgent_Full_Capability_SetMask"}, {253, "AUDIO_RPC_ToAgent_PrivateInfo"},
	{254, "AUDIO_RPC_ToAgent_Capability_SetPassThroughMode"}, {255, "AUDIO_RPC_ToAgent_AI_Device_USBinfo"},
	{300, "AUDIO_RPC_ToAgent_Set_Dummy_Value"}, {301, "AUDIO_RPC_ToAgent_Set_EQ_Table"},
	{1010, "VIDEO_RPC_ToAgent_Create"}, {1020, "VIDEO_RPC_ToAgent_Connect"},
	{1030, "VIDEO_RPC_ToAgent_InitRingBuffer"}, {1040, "VIDEO_RPC_ToAgent_Run"},
	{1050, "VIDEO_RPC_ToAgent_Pause"}, {1060, "VIDEO_RPC_ToAgent_Stop"},
	{1070, "VIDEO_RPC_ToAgent_Destroy"}, {1080, "VIDEO_RPC_ToAgent_Flush"},
	{1090, "VIDEO_RPC_ToAgent_SetRefClock"}, {1091, "VIDEO_RPC_ToAgent_ConfigWriteBackFlow"},
	{1100, "VIDEO_RPC_ToAgent_VideoCreate"}, {1105, "VIDEO_RPC_ToAgent_VideoConfig"},
	{1108, "VIDEO_RPC_ToAgent_VideoMemoryConfig"}, {1109, "VIDEO_RPC_ToAgent_VideoChunkConfig"},
	{1110, "VIDEO_RPC_ToAgent_VideoDestroy"}, {1120, "VIDEO_RPC_ToAgent_RequestBuffer"},
	{1130, "VIDEO_RPC_ToAgent_ReleaseBuffer"}, {1131, "VIDEO_RPC_ToAgent_SetFullHDBuffer"},
	{1132, "VIDEO_RPC_ToAgent_FillBuffer"}, {1133, "VIDEO_RPC_ToAgent_ConfigLowDelay"},
	{1135, "VIDEO_RPC_ToAgent_ConfigChannelLowDelay"}, {1140, "VIDEO_RPC_ToAgent_SetDebugMemory"},
	{1150, "VIDEO_RPC_ToAgent_VideoHalt"}, {1160, "VIDEO_RPC_ToAgent_YUYV2RGB"},
	{1165, "VIDEO_RPC_ToAgent_PrivateInfo"}, {2010, "VIDEO_RPC_VOUT_ToAgent_SetVideoStandard"},
	{2011, "VIDEO_RPC_VOUT_ToAgent_SetHDMI"}, {2012, "VIDEO_RPC_VOUT_ToAgent_ConfigHDMI"},
	{2013, "VIDEO_RPC_VOUT_ToAgent_ConfigHdmiInfoFrame"}, {2014, "VIDEO_RPC_VOUT_ToAgent_ConfigVideoStandard"},
	{2015, "VIDEO_RPC_VOUT_ToAgent_ConfigTVSystem"}, {2016, "VIDEO_RPC_VOUT_ToAgent_AnaglyphConversion"},
	{2340, "VIDEO_RPC_VOUT_ToAgent_ConfigMacroVision"}, {2020, "VIDEO_RPC_VOUT_ToAgent_SetTVtype"},
	{2030, "VIDEO_RPC_VOUT_ToAgent_SetBackground"}, {2031, "VIDEO_RPC_VOUT_ToAgent_SetMixerOrder"},
	{2032, "VIDEO_RPC_VOUT_ToAgent_GetMixerOrder"}, {2040, "VIDEO_RPC_VOUT_ToAgent_SetClosedCaption"},
	{2050, "VIDEO_RPC_VOUT_ToAgent_SetAPS"}, {2060, "VIDEO_RPC_VOUT_ToAgent_SetCopyMode"},
	{2070, "VIDEO_RPC_VOUT_ToAgent_SetAspectRatio"}, {2080, "VIDEO_RPC_VOUT_ToAgent_ConfigureDisplayWindow"},
	{2081, "VIDEO_RPC_VOUT_ToAgent_ConfigureDisplayWindowZoomWin"}, {2083, "VIDEO_RPC_VOUT_ToAgent_ConfigureDisplayWindowDispZoomWin"},
	{2085, "VIDEO_RPC_VOUT_ToAgent_PMixer_ConfigurePlaneMixer"}, {2087, "VIDEO_RPC_VOUT_ToAgent_3D_ConfigureShiftOffset"},
	{2100, "VIDEO_RPC_VOUT_ToAgent_SetRescaleMode"}, {2110, "VIDEO_RPC_VOUT_ToAgent_SetDeintMode"},
	{2120, "VIDEO_RPC_VOUT_ToAgent_Zoom"}, {2121, "VIDEO_RPC_VOUT_ToAgent_Pan_Zoom"},
	{2122, "VIDEO_RPC_VOUT_ToAgent_SetTransparency"}, {2123, "VIDEO_RPC_VOUT_ToAgent_Actual_Zoom"},
	{2124, "VIDEO_RPC_VOUT_ToAgent_SetWatermark"}, {2130, "VIDEO_RPC_VOUT_ToAgent_ConfigureOSD"},
	{2131, "VIDEO_RPC_VOUT_ToAgent_ConfigureOSDPalette"}, {2140, "VIDEO_RPC_VOUT_ToAgent_CreateOSDwindow"},
	{2141, "VIDEO_RPC_VOUT_ToAgent_SetOSDwindowPalette"}, {2150, "VIDEO_RPC_VOUT_ToAgent_ModifyOSDwindow"},
	{2151, "VIDEO_RPC_VOUT_ToAgent_ModifyOSDwindowOnGo"}, {2160, "VIDEO_RPC_VOUT_ToAgent_DeleteOSDwindow"},
	{2161, "VIDEO_RPC_VOUT_ToAgent_DeleteOSDwindowOnGo"}, {2170, "VIDEO_RPC_VOUT_ToAgent_DrawOSDwindow"},
	{2171, "VIDEO_RPC_VOUT_ToAgent_DrawOSDwindowOnGo"}, {2180, "VIDEO_RPC_VOUT_ToAgent_HideOSDwindow"},
	{2181, "VIDEO_RPC_VOUT_ToAgent_HideOSDwindowOnGo"}, {2182, "VIDEO_RPC_VOUT_ToAgent_ConfigOSDCanvas"},
	{2183, "VIDEO_RPC_VOUT_ToAgent_ConfigureGraphicCanvas"}, {2184, "VIDEO_RPC_VOUT_ToAgent_CreateGraphicWindow"},
	{2185, "VIDEO_RPC_VOUT_ToAgent_HideGraphicWindow"}, {2186, "VIDEO_RPC_VOUT_ToAgent_ModifyGraphicWindow"},
	{2187, "VIDEO_RPC_VOUT_ToAgent_DeleteGraphicWindow"}, {2188, "VIDEO_RPC_VOUT_ToAgent_DrawGraphicWindow"},
	{2189, "VIDEO_RPC_VOUT_ToAgent_DisplayGraphic"}, {2190, "VIDEO_RPC_VOUT_ToAgent_ConfigureCursor"},
	{2192, "VIDEO_RPC_VOUT_ToAgent_ConfigureMarsCursor"}, {2200, "VIDEO_RPC_VOUT_ToAgent_DrawCursor"},
	{2210, "VIDEO_RPC_VOUT_ToAgent_HideCursor"}, {2220, "VIDEO_RPC_VOUT_ToAgent_SetPeakingStrength"},
	{2230, "VIDEO_RPC_VOUT_ToAgent_SetBrightness"}, {2235, "VIDEO_RPC_VOUT_ToAgent_SetVideoBrightness"},
	{2237, "VIDEO_RPC_VOUT_ToAgent_SetV2VideoBrightness"}, {2240, "VIDEO_RPC_VOUT_ToAgent_SetHue"},
	{2245, "VIDEO_RPC_VOUT_ToAgent_SetVideoHue"}, {2247, "VIDEO_RPC_VOUT_ToAgent_SetV2VideoHue"},
	{2248, "VIDEO_RPC_VOUT_ToAgent_SetLportColor"}, {2250, "VIDEO_RPC_VOUT_ToAgent_SetSaturation"},
	{2251, "VIDEO_RPC_VOUT_ToAgent_SetV2VideoContrast"}, {2252, "VIDEO_RPC_VOUT_ToAgent_SetVideoSaturation"},
	{2253, "VIDEO_RPC_VOUT_ToAgent_SetV2VideoSaturation"}, {2254, "VIDEO_RPC_VOUT_ToAgent_SetVideoContrast"},
	{2255, "VIDEO_RPC_VOUT_ToAgent_SetContrast"}, {2256, "VIDEO_RPC_VOUT_ToAgent_ConfigColorMatrix"},
	{2257, "VIDEO_RPC_VOUT_ToAgent_VideoCapture"}, {2258, "VIDEO_RPC_VOUT_ToAgent_SetSubtitleYoffset"},
	{2259, "VIDEO_RPC_VOUT_ToAgent_SwitchSPDomination"}, {2350, "VIDEO_RPC_VOUT_ToAgent_DisplayWinAnimation"},
	{2351, "VIDEO_RPC_VOUT_ToAgent_SetVideoSharpness"}, {2260, "VIDEO_RPC_VO_FILTER_ToAgent_Display"},
	{2270, "VIDEO_RPC_VO_FILTER_ToAgent_Capture"}, {2290, "VIDEO_RPC_VO_FILTER_ToAgent_SetSpeed"},
	{2300, "VIDEO_RPC_VO_FILTER_ToAgent_Step"}, {2310, "VIDEO_RPC_VO_FILTER_ToAgent_ShowStillPicture"},
	{2320, "VIDEO_RPC_VO_FILTER_ToAgent_FillVideoBorder"}, {2330, "VIDEO_RPC_VO_FILTER_ToAgent_SetFastDisplay"},
	{2331, "VIDEO_RPC_VO_FILTER_ToAgent_DestroyTranscodeBuffer"}, {2335, "VIDEO_RPC_VO_FILTER_ToAgent_PrivateInfo"},
	{2345, "VIDEO_RPC_VOUT_ToAgent_VideoRotate"}, {2355, "VIDEO_RPC_VOUT_ToAgent_Set_Q_Parameter"},
	{2365, "VIDEO_RPC_VOUT_ToAgent_QueryDisplayWin"}, {2366, "VIDEO_RPC_VOUT_ToAgent_QueryDisplayWinNew"},
	{2370, "VIDEO_RPC_VOUT_ToAgent_QueryGraphicWinInfo"}, {2375, "VIDEO_RPC_VOUT_QUERY"},
	{2376, "VIDEO_RPC_VOUT_ToAgent_KeepCurPicSVP"}, {2377, "VIDEO_RPC_VOUT_ToAgent_KeepV1CurPic"},
	{2378, "VIDEO_RPC_VOUT_ToAgent_KeepCurPic"}, {2379, "VIDEO_RPC_VOUT_ToAgent_KeepCurPic_FW_Malloc"},
	{2380, "VIDEO_RPC_VOUT_ToAgent_Set_3D_Sub"}, {2384, "VIDEO_RPC_VOUT_ToAgent_Set_3D_to_2D"},
	{2390, "VIDEO_RPC_VOUT_ToAgent_Set_DeintFlag"}, {2400, "VIDEO_RPC_VOUT_ToAgent_Set_EnhancedSDR"},
	{2405, "VIDEO_RPC_VOUT_ToAgent_Set_HDMIHDRMetadata"}, {2410, "VIDEO_RPC_VOUT_ToAgent_Query_TV_Capability"},
	{2420, "VIDEO_RPC_VOUT_NPP_Init"}, {2421, "VIDEO_RPC_VOUT_NPP_Destroy"},
	{5010, "VIDEO_RPC_SUBPIC_DEC_ToAgent_EnableSubPicture"}, {5020, "VIDEO_RPC_SUBPIC_DEC_ToAgent_ShowSubPicture"},
	{5030, "VIDEO_RPC_SUBPIC_DEC_ToAgent_HideSubPicture"}, {5035, "VIDEO_RPC_SUBPIC_DEC_ToAgent_Flush"},
	{5040, "VIDEO_RPC_SUBPIC_DEC_ToAgent_ConfigResolution"}, {5050, "VIDEO_RPC_ToAgent_Get_EDID_Data"},
	{5055, "VIDEO_RPC_ToAgent_set_HDMI_VRR"}, {5060, "VIDEO_RPC_VOUT_ToAgent_QueryConfigTVSystem"},
	{5061, "VIDEO_RPC_Transcode_FlushICQByID"}, {5070, "AUDIO_RPC_ToAgent_AIO_PrivateInfo"},
	{5080, "AUDIO_RPC_ToAgent_AudioDecoderMonitering"}, {5090, "AUDIO_RPC_ToAgent_Dec_PrivateInfo"},
	{5100, "RPC_FW_Query_Dbg_Info"}, {5200, "VIDEO_RPC_VOUT_ToAgent_DV_ControlPath_Info"},
	{5300, "AUDIO_RPC_ToAgent_PP_PrivateInfo"}, {5400, "VIDEO_RPC_ToAgent_OutputControl_Create"},
	{5500, "VIDEO_RPC_ToAgent_OutputControl_NotifyHdcpStatus"}, {5600, "VIDEO_RPC_ToAgent_OutputControl_GetStatus"},
	{5700, "VIDEO_RPC_ToAgent_OutputControl_PrivateInfo"}
};

static struct id_name procedureID_v_system2agent[] = {
	{10, "VIDEO_RPC_COMMON_ToAgent_Create"}, {20, "VIDEO_RPC_COMMON_ToAgent_Connect"},
	{30, "VIDEO_RPC_COMMON_ToAgent_InitRingBuffer"}, {40, "VIDEO_RPC_COMMON_ToAgent_Run"},
	{50, "VIDEO_RPC_COMMON_ToAgent_Pause"}, {60, "VIDEO_RPC_COMMON_ToAgent_Stop"},
	{70, "VIDEO_RPC_COMMON_ToAgent_Destroy"}, {80, "VIDEO_RPC_COMMON_ToAgent_Flush"},
	{90, "VIDEO_RPC_COMMON_ToAgent_SetRefClock"}, {100, "VIDEO_RPC_COMMON_ToAgent_VideoCreate"},
	{105, "VIDEO_RPC_COMMON_ToAgent_VideoConfig"}, {108, "VIDEO_RPC_COMMON_ToAgent_VideoMemoryConfig"},
	{109, "VIDEO_RPC_COMMON_ToAgent_VideoChunkConfig"}, {110, "VIDEO_RPC_COMMON_ToAgent_VideoDestroy"},
	{120, "VIDEO_RPC_COMMON_ToAgent_RequestBuffer"}, {130, "VIDEO_RPC_COMMON_ToAgent_ReleaseBuffer"},
	{133, "VIDEO_RPC_COMMON_ToAgent_ConfigLowDelay"}, {140, "VIDEO_RPC_COMMON_ToAgent_SetDebugMemory"},
	{141, "VIDEO_RPC_COMMON_ToAgent_VCPU_DEBUG_COMMAND"}, {150, "VIDEO_RPC_COMMON_ToAgent_VideoHalt"},
	{160, "VIDEO_RPC_COMMON_ToAgent_YUYV2RGB"}, {170, "VIDEO_RPC_COMMON_ToAgent_Self_Destroy"},
	{550, "VIDEO_RPC_ToAgent_SetResourceInfo"}, {1005, "VIDEO_RPC_DEC_ToAgent_CmprsCtrl"},
	{1006, "VIDEO_RPC_DEC_ToAgent_DecimateCtrl"}, {1010, "VIDEO_RPC_DEC_ToAgent_SetSpeed"},
	{1015, "VIDEO_RPC_DEC_ToAgent_SetErrorConcealmentLevel"}, {1020, "VIDEO_RPC_DEC_ToAgent_Init"},
	{1030, "VIDEO_RPC_DEC_ToAgent_SetDeblock"}, {1035, "VIDEO_RPC_DEC_ToAgent_GetVideoSequenceInfo"},
	{1036, "VIDEO_RPC_DEC_ToAgent_GetVideoSequenceInfo_New"}, {1040, "VIDEO_RPC_DEC_ToAgent_BitstreamValidation"},
	{1045, "VIDEO_RPC_DEC_ToAgent_Capability"}, {1050, "VIDEO_RPC_DEC_ToAgent_SetDecoderCCBypass"},
	{1060, "VIDEO_RPC_DEC_ToAgent_SetDNR"}, {1065, "VIDEO_RPC_DEC_ToAgent_SetRefSyncLimit"},
	{1085, "VIDEO_RPC_FLASH_ToAgent_SetOutput"}, {1070, "VIDEO_RPC_THUMBNAIL_ToAgent_SetVscalerOutputFormat"},
	{1080, "VIDEO_RPC_THUMBNAIL_ToAgent_SetThreshold"}, {3090, "VIDEO_RPC_VOUT_ToAgent_SetV2alpha"},
	{1090, "VIDEO_RPC_THUMBNAIL_ToAgent_SetStartPictureNumber"}, {1095, "VIDEO_RPC_DEC_ToAgent_PrivateInfo"},
	{5040, "VIDEO_RPC_SUBPIC_DEC_ToAgent_Configure"}, {5050, "VIDEO_RPC_SUBPIC_DEC_ToAgent_Page"},
	{6010, "VIDEO_RPC_JPEG_ToAgent_DEC"}, {6011, "VIDEO_RPC_JPEG_ToAgent_DEC_BATCH"},
	{6020, "VIDEO_RPC_TRANSITION_ToAgent_Start"}, {8010, "VIDEO_RPC_MIXER_FILTER_ToAgent_Configure"},
	{8020, "VIDEO_RPC_MIXER_FILTER_ToAgent_ConfigureWindow"}, {8030, "VIDEO_RPC_MIXER_FILTER_ToAgent_SetMasterWindow"},
	{8040, "VIDEO_RPC_MIXER_ToAgent_PlayOneMotionJpegFrame"}
};

static struct id_name procedureID_to_rprogram[] = {
	{1, "RPC_REMOTE_CMD_ALLOC"}, {2, "RPC_REMOTE_CMD_FREE"}, {3, "RPC_REMOTE_CMD_ALLOC_SECURE_LEGACY"}
};

static struct id_name procedureID_hifi_agent[] = {
	{1, "AUDIO2_RPC_ToAgent_Create"}, {2, "AUDIO2_RPC_ToAgent_InitRingBufferHeader"},
	{3, "AUDIO2_RPC_ToAgent_Run"}, {4, "AUDIO2_RPC_ToAgent_Pause"},
	{5, "AUDIO2_RPC_ToAgent_Stop"}, {6, "AUDIO2_RPC_ToAgent_Destroy"},
	{7, "AUDIO2_RPC_ToAgent_SetRefClock"}, {8, "AUDIO2_RPC_ToAgent_PrivateInfo"},
	{9, "AUDIO2_RPC_ToAgent_AIO_PrivateInfo"}, {11, "AUDIO2_RPC_ToAgent_Connect"},
	{12, "AUDIO2_RPC_ToAgent_SwitchFocus"}, {13, "AUDIO2_RPC_ToAgent_Flush"},
	{14, "AUDIO2_RPC_ToAgent_AudioConfig"}, {15, "AUDIO2_RPC_ToAgent_Dec_PrivateInfo"},
	{16, "AUDIO2_RPC_ToAgent_SetSeeking"}, {17, "AUDIO2_RPC_ToAgent_PP_InitPin"},
	{18, "AUDIO2_RPC_ToAgent_EndOfStream"}, {19, "AUDIO2_RPC_ToAgent_HDMI_Mute"},
	{20, "AUDIO2_RPC_ToAgent_AO_Only_Switchfocus"}, {21, "AUDIO2_RPC_ToAgent_AOUT_Drop_Sample"},
	{22, "AUDIO2_RPC_ToAgent_AOUT_HDMI_Set"}, {23, "AUDIO2_RPC_ToAgent_AOUT_SPDIF_Source"},
	{24, "AUDIO2_RPC_ToAgent_AOUT_Copy_Source"}, {25, "AUDIO2_RPC_ToAgent_HDMI_OUT_VSDB"},
	{26, "AUDIO2_RPC_ToAgent_HDMI_OUT_EDID2"}, {27, "AUDIO2_RPC_ToAgent_MS12v2_6_Init_Cfg"},
	{28, "AUDIO2_RPC_ToAgent_MS12v2_6_Runtime_Cfg"}, {29, "AUDIO2_RPC_ToAgent_MS12v2_6_Update_Param"},
	{30, "AUDIO2_RPC_ToAgent_InitRingBufferHeaderExt"}, {31, "AUDIO2_RPC_ToAgent_set_debug_flag"},
	{33, "AUDIO2_RPC_ToAgent_MS12v2_6_2_Init_Cfg"}, {34, "AUDIO2_RPC_ToAgent_MS12v2_6_2_Runtime_Cfg"},
	{35, "AUDIO2_RPC_ToAgent_MS12v2_6_Single_Update_Param"}, {36, "AUDIO2_RPC_ToAgent_BitstreamValidation"},
	{37, "AUDIO2_RPC_ToAgent_AudioDecoderMonitering"}, {38, "AUDIO2_RPC_ToAgent_PP_PrivateInfo"},
	{39, "AUDIO_RPC_ToAgent_PP_EQ_Config"}, {40, "AUDIO_RPC_ToAgent_PP_PTS_MIXER_Config"}
};

struct id_map {
	int id;
	struct id_name *map;
	size_t map_size;
};

static struct id_map programID_to_procedureID_rpc[] = {
	{RPC_PG_ID_R_PROGRAM, procedureID_to_rprogram, sizeof(procedureID_to_rprogram)},
	{RPC_PG_ID_AUDIO_SYSTEM * 1, procedureID_a_system2agent, sizeof(procedureID_a_system2agent)},
	{RPC_PG_ID_AUDIO_SYSTEM * 5, procedureID_v_system2agent, sizeof(procedureID_v_system2agent)},
	{RPC_PG_ID_AUDIO_AGENT, procedureID_a_agent2system, sizeof(procedureID_a_agent2system)},
	{RPC_PG_ID_VIDEO_AGENT, procedureID_v_agent2system, sizeof(procedureID_v_agent2system)},
	{RPC_PG_ID_HIFI_AGENT, procedureID_hifi_agent, sizeof(procedureID_hifi_agent)},
};

static struct id_map programID_to_procedureID_rpmsg[] = {
	{RPC_PG_ID_R_PROGRAM, procedureID_to_rprogram, sizeof(procedureID_to_rprogram)},
	{RPC_PG_ID_AUDIO_SYSTEM * 1, procedureID_a_system2agent, sizeof(procedureID_a_system2agent)},
	{RPC_PG_ID_AUDIO_SYSTEM * 2, procedureID_v_system2agent, sizeof(procedureID_v_system2agent)},
	{RPC_PG_ID_AUDIO_AGENT, procedureID_a_agent2system, sizeof(procedureID_a_agent2system)},
	{RPC_PG_ID_VIDEO_AGENT, procedureID_v_agent2system, sizeof(procedureID_v_agent2system)},
	{RPC_PG_ID_HIFI_AGENT, procedureID_hifi_agent, sizeof(procedureID_hifi_agent)},
};

static const char *procedureID_name(__u32 programID, __u32 procedureID, int rpc_num, bool use_rpc_mode)
{
	struct id_map *map = use_rpc_mode ? programID_to_procedureID_rpc : programID_to_procedureID_rpmsg;
	int map_size = use_rpc_mode ? sizeof(programID_to_procedureID_rpc) : sizeof(programID_to_procedureID_rpmsg);
	int key = programID;

	if (programID == RPC_PG_ID_AUDIO_SYSTEM)
		key = programID * rpc_num;

	for (int i = 0; i < map_size / sizeof(struct id_map); i++) {
		if (map[i].id == key) {
			const char *name = map_lookup(map[i].map, map[i].map_size, procedureID);
			if (name)
				return name;
		}
	}

	static char buf[10];
	snprintf(buf, sizeof(buf), "%d", procedureID);
	return buf;
}

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static int get_uptime(long *uptime_secs)
{
	FILE *fp = fopen("/proc/uptime", "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%ld", uptime_secs) != 1) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

int main(int argc, char **argv)
{
	struct rpcundone_bpf *skel;
	struct argparse argparse;
	int err;
	bool use_rpc_mode = false;
	struct utsname un;

	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, doc, "\n");
	argc = argparse_parse(&argparse, argc, (const char **)argv);

	libbpf_set_print(libbpf_print_fn);
	if (uname(&un) == 0) {
		int major, minor;
		if (sscanf(un.release, "%d.%d", &major, &minor) == 2) {
			if (major > 5 || (major == 5 && minor >= 15)) {
				use_rpc_mode = false; // USE_RPMSG
			} else {
				use_rpc_mode = true; // USE_RPC
			}
		}
	}

	if (use_rpc_mode) {
		if (!tracepoint_exists("rtk_rpc", "rtk_rpc_peek_rpc_request") ||
				!tracepoint_exists("rtk_rpc", "rtk_rpc_peek_rpc_reply")) {
			fprintf(stderr, "ERROR: Required Realtek customized tracing events\n");
			return 1;
		}
	}

	skel = rpcundone_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	bpf_program__set_autoload(skel->progs.rtk_rpc_peek_rpc_request, use_rpc_mode);
	bpf_program__set_autoload(skel->progs.rtk_rpc_peek_rpc_reply, use_rpc_mode);
	bpf_program__set_autoload(skel->progs.__rtk_rpmsg_send, !use_rpc_mode);
	bpf_program__set_autoload(skel->progs.__rtk_rpmsg_send_ret, !use_rpc_mode);
	bpf_program__set_autoload(skel->progs.get_ring_data, !use_rpc_mode);
	bpf_program__set_autoload(skel->progs.get_ring_data_ret, !use_rpc_mode);

	err = rpcundone_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	err = rpcundone_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!exiting) {
		sleep(1);

		if (!env.noclear)
			printf("\e[1;1H\e[2J");
		else
			printf("\n");

		if (env.timestamp) {
			char ts[32];
			time_t t = time(NULL);
			strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
			printf("%-8s\n", ts);
		}

		long uptime_secs;
		if (get_uptime(&uptime_secs) != 0) {
			fprintf(stderr, "Failed to read uptime\n");
			break;
		}

		if (env.fulldisplay) {
			printf("%-14s %6s %6s %6s %1s %12s %9s %-60s %13s %13s %6s %18s\n",
					"COMM", "TGID", "PID", "P_TYPE", "B",
					"programID", "versionID", "procedureID", "parameterSize",
					"mycontext", "second",
					use_rpc_mode ? "90K_clk" : "BPF_time(ns)");
		} else {
			printf("%-14s %6s %6s %6s %1s %12s %-60s %6s %18s\n",
					"COMM", "TGID", "PID", "P_TYPE", "B", "programID",
					"procedureID", "second",
					use_rpc_mode ? "90K_clk" : "BPF_time(ns)");
		}

		int start_fd = bpf_map__fd(skel->maps.start);
		void *lookup_key = NULL;
		__u32 next_key;
		struct event v;

		while (bpf_map_get_next_key(start_fd, lookup_key, &next_key) == 0) {
			if (bpf_map_lookup_elem(start_fd, &next_key, &v) != 0) {
				fprintf(stderr, "bpf_map_lookup_elem failed\n");
				lookup_key = &next_key;
				continue;
			}

			if (env.fulldisplay) {
				printf("%-14.14s %6d %6d %6s %1s %12s %9u %-60s %13u %13u %6ld %18llu\n",
						v.comm, v.tgid, v.pid, v.rpc_num ? "user" : "kernel",
						v.taskID ? "Y" : "N",
						programID_name(v.programID),
						v.versionID,
						procedureID_name(v.programID, v.procedureID, v.rpc_num, use_rpc_mode),
						v.parameterSize, v.mycontext,
						uptime_secs - (long)(v.delta / 1000000000ULL),
						v.refclk);
			} else {
				printf("%-14.14s %6d %6d %6s %1s %12s %-60s %6ld %18llu\n",
						v.comm, v.tgid, v.pid, v.rpc_num ? "user" : "kernel",
						v.taskID ? "Y" : "N",
						programID_name(v.programID),
						procedureID_name(v.programID, v.procedureID, v.rpc_num, use_rpc_mode),
						uptime_secs - (long)(v.delta / 1000000000ULL),
						v.refclk);
			}
			lookup_key = &next_key;
		}	}

	printf("Detaching...\n");

cleanup:
	rpcundone_bpf__destroy(skel);
	return -err;
}
