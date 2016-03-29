#define LOG_TAG "RilWrapper"
#define RIL_SHLIB
#include <telephony/ril_cdma_sms.h>
#include <sys/system_properties.h>
#include <telephony/librilutils.h>
#include <cutils/sockets.h>
#include <telephony/ril.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <utils/Log.h>
#include <sys/stat.h>
#include <pthread.h>
#include <termios.h>
#include <alloca.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#define REAL_RIL_NAME				"/vendor/lib/librapid-ril-core.so"


static int make_argv(char * args, char ** argv) {
    // Note: reserve argv[0]
    int count = 1;
    char * tok;
    char * s = args;

    while ((tok = strtok(s, " \0"))) {
        argv[count] = tok;
        s = NULL;
        count++;
    }
    return count;
}

static RIL_RadioFunctions const *mRealRadioFuncs;
static const struct RIL_Env *mEnv;

static void rilOnRequest(int request, void *data, size_t datalen, RIL_Token t)
{
    switch (request) {
        case RIL_REQUEST_ENTER_SIM_PIN:
            mRealRadioFuncs->onRequest(request, data, datalen, t);
            mRealRadioFuncs->onRequest(RIL_REQUEST_SET_NETWORK_SELECTION_AUTOMATIC, NULL, 0, 0xffffffff);
            break;
        default:
            mRealRadioFuncs->onRequest(request, data, datalen, t);
    }
}

const RIL_RadioFunctions* RIL_Init(const struct RIL_Env *env, int argc, char **argv)
{
	RIL_RadioFunctions const* (*fRealRilInit)(const struct RIL_Env *env, int argc, char **argv);
	static RIL_RadioFunctions rilInfo;
	void *realRilLibHandle;
	int i;

        char **rilArgv;
        static char * newArgv[32];
        static char args[2048] = "-a /dev/gsmtty12 -n /dev/gsmtty2 -m /dev/gsmtty6 -c /dev/gsmtty8 -u /dev/gsmtty1 -o /dev/gsmtty9 -d /dev/gsmtty3 -d /dev/gsmtty4 -d /dev/gsmtty15 -d /dev/gsmtty16 -d /dev/gsmtty17";
        rilArgv = newArgv;
        argc = make_argv(args, newArgv);

	//save the env;
	mEnv = env;

	//get the real RIL
	realRilLibHandle = dlopen(REAL_RIL_NAME, RTLD_LOCAL);
	if (!realRilLibHandle) {
		RLOGE("Failed to load the real RIL '" REAL_RIL_NAME  "': %s\n", dlerror());
		return NULL;
	}

	//load the real RIL
	fRealRilInit = dlsym(realRilLibHandle, "RIL_Init");
	if (!fRealRilInit) {
		RLOGE("Failed to find the real RIL's entry point\n");
		goto out_fail;
	}

	RLOGD("Calling the real RIL's entry point with %u args\n", argc);
	for (i = 0; i < argc; i++)
		RLOGD("  argv[%2d] = '%s'\n", i, rilArgv[i]);

	//try to init the real ril
	mRealRadioFuncs = fRealRilInit(env, argc, rilArgv);
	if (!mRealRadioFuncs) {
		RLOGE("The real RIL's entry point failed\n");
		goto out_fail;
	}

	//copy the real RIL's info struct, then replace the onRequest pointer with our own
	rilInfo = *mRealRadioFuncs;
	rilInfo.onRequest = rilOnRequest;

	RLOGD("Wrapped RIL version is '%s'\n", mRealRadioFuncs->getVersion());

	//we're all good - return to caller
	return &rilInfo;

out_fail:
	dlclose(realRilLibHandle);
	return NULL;
}
