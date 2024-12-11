#include "pch.h"
#include <Windows.h>
#include <httpserv.h>
#include "HttpFactory.h"

CMyHttpModuleFactory * pFactory = NULL;


HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo * pModuleInfo, IHttpServer * pHttpServer)
{
    HRESULT hr = S_OK;
    
    pFactory = new CMyHttpModuleFactory(); 
    pModuleInfo->SetRequestNotifications(pFactory, RQ_BEGIN_REQUEST|RQ_SEND_RESPONSE, 0);

    pModuleInfo->SetPriorityForRequestNotification(RQ_BEGIN_REQUEST, PRIORITY_ALIAS_FIRST);
    pModuleInfo->SetPriorityForRequestNotification(RQ_SEND_RESPONSE, PRIORITY_ALIAS_FIRST);

    return hr;
}

