#include "Formats.h"
#include "resource.h"
//#include <TlHelp32.h>


// Copy from MSDN  
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Global variables
#define Info_Lable			7000
#define Format_Lable		7001
#define UCase_RadButton		6000  
#define LCase_RadButton		6001 
#define Execute_Button		8881  
#define Setting_Button		8882  
#define Clear_Button		8883
#define Stop_Button			8884  
#define About_Button		8885  
#define Input_Editbox		9001  
#define Output_Editbox		9002  
#define Progress_Bar		10001  
#define LOGO_dlgwin			5000

#define FunctionButton_Y	260

static ProgressStrcure PB;
static Settings ST;

//Current Path
TCHAR* CurrentPath = NULL;
//Overall handles
static WNDPROC OldEditProc = NULL;
static HANDLE hDropThread = NULL;
static HANDLE hPBThread = NULL;
static HWND hWndExcButton = NULL;
static HWND hWndSettingButton = NULL;
static HWND hWndClearButton = NULL;
static HWND hWndAboutButton = NULL;
static HWND hWndStopButton = NULL;
static HWND hWndInText = NULL;
static HWND hWndOutText = NULL;
static HWND hWndPB = NULL;
static HWND hWndLable = NULL;
static HWND hWndFormatLable = NULL;
static HWND hWndUCButton = NULL;
static HWND hWndLCButton = NULL;

static HWND hWnddlgLOGO = NULL;

static HWND hdlgAbout = NULL;
static HWND hdlgSetting = NULL;

// Size of filesize text buffer
#define FileSizeBufferLen	32
// Size of shared memery buffer
#define BUF_SIZE 256


// The main window class name.
static TCHAR szWindowClass[] = _T("HashMEWindow");

// The string that appears in the application's title bar.
static TCHAR szTitle[] = HashME_WindowTitle;

//Indicate if application has started before
static bool SingleInstance = true;

HINSTANCE hInst;

HICON DlgLOGO = NULL;
// Timer
uint32_t dwTimeBegin, dwTimeEnd;



// Forward declarations of functions included in this code module:
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK DlgAboutProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK DlgSettingProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK EnumWindowsProc(HWND Enumhwnd, LPARAM lParam);
DWORD WINAPI DropHandelThread(LPVOID wParam);
DWORD WINAPI StartHandelThread(LPVOID wParam);
DWORD WINAPI PBThreadProc(LPVOID lpParameter);
void HashME_Mem();
void HashmeFileProcess(ProgressStrcure* PB, Settings* ST);
void InitHashME(HWND hWnd, Settings *ST);
void RegRead(Settings *ST);
int RegWrite(Settings *ST, int para);

int WINAPI WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow)
{
	LPWSTR *szArgList;
	int argCount;

	TCHAR szName[] = L"HashME30047C53C0102045D185995606A574BC187FBDF4";
	HANDLE hMapFile;
	LPCTSTR pBuf;
	bool clean = false;

	//Commandline process
	szArgList = CommandLineToArgvW(GetCommandLine(), &argCount);
	int bufferlen = _tcslen(szArgList[0]) + 1;
	CurrentPath = new TCHAR[bufferlen];
	wmemcpy_s(CurrentPath, bufferlen, szArgList[0], bufferlen - 1);
	CurrentPath[bufferlen - 1] = L'\0';
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, (LPCTSTR)IDI_ICON1);		//Load icon
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(CreateSolidBrush(RGB(240, 240, 240)));
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = (HICON)LoadImage(hInstance, (LPCTSTR)IDI_ICON1, IMAGE_ICON, 16, 16, LR_SHARED);		//Load smallest icon for title bar. Since ICON1 is already open, use LR_SHARED.	

	if (!RegisterClassEx(&wcex))
	{
		MessageBox(NULL,
			StartError_text,
			_T("HashME"),
			NULL);

		return 1;
	}
	


	hInst = hInstance; // Store instance handle in our global variable

					   // The parameters to CreateWindow explained:
					   // szWindowClass: the name of the application
					   // szTitle: the text that appears in the title bar03.00
					   // WS_OVERLAPPEDWINDOW: the type of window to create
					   // CW_USEDEFAULT, CW_USEDEFAULT: initial position (x, y)
					   // 500, 100: initial size (width, length)
					   // NULL: the parent of this window
					   // NULL: this application does not have a menu bar
					   // hInstance: the first parameter from WinMain
					   // NULL: not used in this application
	HWND hWnd = CreateWindowEx(
		WS_EX_ACCEPTFILES,
		szWindowClass,
		szTitle,
		WS_POPUPWINDOW | WS_CAPTION | WS_MINIMIZEBOX,
		CW_USEDEFAULT, CW_USEDEFAULT,
		597, 372,
		NULL,
		NULL,
		hInstance,
		NULL
		);

	if (!hWnd)
	{
		MessageBox(NULL,
			StartError_text,
			_T("HashMe"),
			NULL);

		return 1;
	}
	if (ST.singleinstance)
	{
		hMapFile = OpenFileMapping(
			FILE_MAP_ALL_ACCESS,   // read/write access
			FALSE,                 // do not inherit the name
			szName);               // name of mapping object
		clean = true;
		if (hMapFile == NULL)
		{
			hMapFile = CreateFileMapping(
				INVALID_HANDLE_VALUE,    // use paging file
				NULL,                    // default security
				PAGE_READWRITE,          // read/write access
				0,                       // maximum object size (high-order DWORD)
				BUF_SIZE,                // maximum object size (low-order DWORD)
				szName);                 // name of mapping object

			pBuf = (LPTSTR)MapViewOfFile(hMapFile,   // handle to map object
				FILE_MAP_ALL_ACCESS, // read/write permission
				0,
				0,
				BUF_SIZE);
			CopyMemory((PVOID)pBuf, &hWnd, sizeof(hWnd));
		}
		else
		{
			//Sleep(100);
			pBuf = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
			HWND *PrevWindHandle = (HWND*)pBuf;
			SendMessage(*PrevWindHandle, WM_SYSCOMMAND, SC_RESTORE, 0);
			SetForegroundWindow(*PrevWindHandle);
			UnmapViewOfFile(pBuf);
			CloseHandle(hMapFile);
			return 0;
		}
	}
	

	// The parameters to ShowWindow explained:
	// hWnd: the value returned from CreateWindow
	// nCmdShow: the fourth parameter from WinMain
	ShowWindow(hWnd,
		nCmdShow);
	UpdateWindow(hWnd);

	if (argCount > 1)
	{
		int TotalNumberOfFiles = argCount - 1;								//total number of files to process
		PB.TotalFileToProcess = TotalNumberOfFiles;
		PB.TotalBytesToProcess = 0;
		PB.BytesProcessed = 0;
		PB.szFilepath = new TCHAR*[TotalNumberOfFiles];
		PB.szPrefixedFilepath = new TCHAR*[TotalNumberOfFiles];
		PB.FileSize = new uint64_t[TotalNumberOfFiles];
		PB.szFileSizeText = new TCHAR*[TotalNumberOfFiles];
		for (int i = 0; i < TotalNumberOfFiles; i++)
		{
			int namebufferlen = _tcslen(szArgList[i + 1]) + 1;
			int prefix_namebufferlen = namebufferlen + 4;
			PB.szFilepath[i] = new TCHAR[namebufferlen];
			PB.szPrefixedFilepath[i] = new TCHAR[prefix_namebufferlen];
			PB.szFileSizeText[i] = new TCHAR[FileSizeBufferLen];
			// To get file name, don't use PB.szFilepath[i] = szArgList[i + 1] since it's only pass the pointer to PB.szFilepath. Causing problems when delete[] PB.szFilepath
			wmemcpy_s(PB.szFilepath[i], namebufferlen, szArgList[i + 1], namebufferlen - 1);
			PB.szFilepath[i][namebufferlen - 1] = L'\0';			
			Link2String(FileNamePrefix, PB.szFilepath[i], PB.szPrefixedFilepath[i], prefix_namebufferlen, 0);
			HANDLE hFile = CreateFile(PB.szPrefixedFilepath[i], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				FormatFileErrorOutput(OUTPUT_TEXT_BUFFER, PB.szFilepath[i]);
				PB.FileSize[i] = 0;
				SendMessage(hWndOutText, WM_SETTEXT, NULL, (LPARAM)OUTPUT_TEXT_BUFFER);
				SendMessage(hWndOutText, WM_VSCROLL, SB_BOTTOM, NULL);
			}
			else
			{
				SendMessage(hWndPB, PBM_SETPOS, 2, 0);
				GetFileSizeEx(hFile, &OriFileLengh);
				PB.FileSize[i] = OriFileLengh.QuadPart;
				PB.TotalBytesToProcess += OriFileLengh.QuadPart;
			}
			_ui64tow_s(PB.FileSize[i], PB.szFileSizeText[i], FileSizeBufferLen, 10);
			CloseHandle(hFile);
		}
		PB.Checker = PB.TotalBytesToProcess / 50;
		CreateThread(NULL, 0,StartHandelThread, &PB, 0, NULL);		
	}

	// Main message loop:
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	if (clean)
	{
		UnmapViewOfFile(pBuf);
		CloseHandle(hMapFile);
	}
	delete[] CurrentPath;
	return (int)msg.wParam;
}



//
//  FUNCTION: EditSubProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Input textbox subprocdure, to get user ENTER key. Associate enter with hit HashME button
//
//  WM_CHAR    When a key is pressed
// 
//
static long FAR PASCAL EditSubProc(HWND hWnd, UINT wMessage, WPARAM wParam, LPARAM lParam)
{
	HWND  hDlg = GetParent(hWnd);

	switch (wMessage) {

	case WM_CHAR: {
		if (wParam == VK_RETURN)
		{			
			SendMessage(hDlg, WM_COMMAND, Execute_Button, lParam);		
			return 0;
		}			
		break;
	}
	default:
		break;
		
	}
	return CallWindowProc(OldEditProc, hWnd, wMessage, wParam, lParam);
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{	
	
	uint64_t *FileSize = NULL;	

	switch (message)
	{
	case WM_CREATE:
	{
		INITCOMMONCONTROLSEX InitCtrlEx;
		InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
		InitCtrlEx.dwICC = ICC_PROGRESS_CLASS;
		if (!InitCommonControlsEx(&InitCtrlEx))
			return FALSE;		
		InitCtrlEx.dwICC = ICC_LINK_CLASS;
		if (!InitCommonControlsEx(&InitCtrlEx))
			return FALSE;
		RegRead(&ST);
		InitHashME(hWnd, &ST);
	}
	break;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case Execute_Button:		//Hit Hashme buttom			
			HashME_Mem();
			SendMessage(hWndOutText, WM_VSCROLL, SB_BOTTOM, NULL);
			break;
		case Clear_Button:			//Hit Clear buttom			
			OUTPUT_TEXT_BUFFER[0] = '\0';
			SendMessage(hWndOutText, WM_SETTEXT, NULL, (LPARAM)L"");
			SendMessage(hWndLable, WM_SETTEXT, NULL, (LPARAM)Info_lable_caption);
			SendMessage(hWndPB, PBM_SETPOS, 0, 0);			
			break;
		case About_Button:		//Hit About buttom	
#ifdef CHS
			if (hdlgAbout = CreateDialog(hInst, MAKEINTRESOURCE(IDD_ABOUT_CN), hWnd, (DLGPROC)DlgAboutProc))	
#else
			if (hdlgAbout = CreateDialog(hInst, MAKEINTRESOURCE(IDD_ABOUT), hWnd, (DLGPROC)DlgAboutProc))
#endif
				ShowWindow(hdlgAbout, SW_NORMAL);			
			break;
		case Stop_Button:		//Hit Stop buttom	
			STOP = true;
			break;
		case Setting_Button:
#ifdef CHS
			if (hdlgSetting = CreateDialog(hInst, MAKEINTRESOURCE(IDD_SETTING_CN), hWnd, (DLGPROC)DlgSettingProc))
#else
			if (hdlgSetting = CreateDialog(hInst, MAKEINTRESOURCE(IDD_SETTING), hWnd, (DLGPROC)DlgSettingProc))
#endif
				ShowWindow(hdlgSetting, SW_NORMAL);
			break;
		case UCase_RadButton:
			if (BST_CHECKED == SendMessage(hWndUCButton, BM_GETCHECK, NULL, NULL))
				ST.LetterCase = true;
			break;
		case LCase_RadButton:
			if (BST_CHECKED == SendMessage(hWndLCButton, BM_GETCHECK, NULL, NULL))
				ST.LetterCase = false;
			break;
		default:
			break;
		}
		return 0;
	}
	break;

	case WM_DROPFILES:
		if (WORKING)
			break;
		PB.TotalBytesToProcess = 0;
		PB.BytesProcessed = 0;		
		hDropThread = CreateThread(NULL, 0, DropHandelThread, (HDROP)wParam, 0, NULL);
		CloseHandle(hDropThread);
	break;
		
	case WM_CTLCOLORSTATIC:
	{		
		if (GetDlgCtrlID((HWND)lParam) == Output_Editbox)  //Set the read-only output textbox's color
		{			
			SetBkColor((HDC)wParam, RGB(255, 255, 255));  // White color		
			return (LRESULT)GetStockObject(DC_BRUSH); // return a DC brush.
		}
		else
		{
			return DefWindowProc((HWND)lParam, message, wParam, lParam);
		}
		break;
	}
	
	
	case WM_DESTROY:	
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
		break;
	}

	return 0;
}



// Setting window Proc..
INT_PTR CALLBACK DlgSettingProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch (msg)
	{
	case WM_SYSCOMMAND:
		if (wParam == SC_CLOSE)
		{
			DestroyWindow(hdlg);
		}
		return 0;

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IDOK_ST:		//If click OK, save all settings then exit
			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD5), BM_GETCHECK, NULL, NULL))
				ST.MD5 = true;
			else
				ST.MD5 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD2), BM_GETCHECK, NULL, NULL))
				ST.MD2 = true;
			else
				ST.MD2 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD4), BM_GETCHECK, NULL, NULL))
				ST.MD4 = true;
			else
				ST.MD4 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA1), BM_GETCHECK, NULL, NULL))
				ST.SHA1 = true;
			else
				ST.SHA1 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA224), BM_GETCHECK, NULL, NULL))
				ST.SHA224 = true;
			else
				ST.SHA224 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA256), BM_GETCHECK, NULL, NULL))
				ST.SHA256 = true;
			else
				ST.SHA256 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA384), BM_GETCHECK, NULL, NULL))
				ST.SHA384 = true;
			else
				ST.SHA384 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA512), BM_GETCHECK, NULL, NULL))
				ST.SHA512 = true;
			else
				ST.SHA512 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_CRC32), BM_GETCHECK, NULL, NULL))
				ST.CRC32 = true;
			else
				ST.CRC32 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_CRC16), BM_GETCHECK, NULL, NULL))
				ST.CRC16 = true;
			else
				ST.CRC16 = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_TIME), BM_GETCHECK, NULL, NULL))
				ST.time = true;
			else
				ST.time = false;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_ANSI), BM_GETCHECK, NULL, NULL))
				ST.CharEncoding = Encode_ANSI;
			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_UNICODE), BM_GETCHECK, NULL, NULL))
				ST.CharEncoding = Encode_Unicode;
			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_UTF8), BM_GETCHECK, NULL, NULL))
				ST.CharEncoding = Encode_UTF8;

			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_ENREG), BM_GETCHECK, NULL, NULL))
			{
				if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), BM_GETCHECK, NULL, NULL))
					ST.singleinstance = true;
				else
					ST.singleinstance = false;

				if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), BM_GETCHECK, NULL, NULL))
				{
					if (ST.ShellMenu == false)
					{
						if (RegWrite(&ST, 1) == 0)
							ST.ShellMenu = true;
						else
							MessageBox(hdlg, Registry__error_text, L"HashME", MB_OK | MB_ICONERROR);
					}					
				}
				else
				{
					if (RegWrite(&ST, -1) == 0)
						ST.ShellMenu = false;
					else
						MessageBox(hdlg, Registry__error_text, L"HashME", MB_OK | MB_ICONERROR);					
				}

				if (RegWrite(&ST, 2) == 0)
					ST.UseReg = true;
				else
					MessageBox(hdlg, Registry__error_text, L"HashME", MB_OK | MB_ICONERROR);				
			}
			
			//Disable reg
			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_DISREG), BM_GETCHECK, NULL, NULL))
			{
				if (ST.UseReg == true || ST.ShellMenu == true)
				{
					if (RegWrite(&ST, -2) ==0)
					{
						ST.ShellMenu = false;
						ST.UseReg = false;
						ST.singleinstance = false;
					}
					else
						MessageBox(hdlg, Registry__error_text, L"HashME", MB_OK | MB_ICONERROR);
				}								
			}
			DestroyWindow(hdlg);
			break;
		case IDCANCEL_ST:		//if click Cancel, exit.
			DestroyWindow(hdlg);
			break;
		case IDC_RADIO_ENREG:
			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_ENREG), BM_GETCHECK, NULL, NULL))
			{
				EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), true);	
				EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), true);
				if (ST.ShellMenu != (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), BM_GETCHECK, NULL, NULL)))
					Button_SetElevationRequiredState(GetDlgItem(hdlg, IDOK_ST), true);
				else
					Button_SetElevationRequiredState(GetDlgItem(hdlg, IDOK_ST), false);
			}			
			break;
		case IDC_RADIO_DISREG:
			if (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_RADIO_DISREG), BM_GETCHECK, NULL, NULL))
			{
				EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), false);
				EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), false);
				if (ST.ShellMenu == true)
					Button_SetElevationRequiredState(GetDlgItem(hdlg, IDOK_ST), true);
				else
					Button_SetElevationRequiredState(GetDlgItem(hdlg, IDOK_ST), false);
			}
			break;	
		case IDC_CHECK_SHELLMENU:
			if (ST.ShellMenu == (BST_CHECKED == SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), BM_GETCHECK, NULL, NULL)))
				Button_SetElevationRequiredState(GetDlgItem(hdlg, IDOK_ST), false);
			else
				Button_SetElevationRequiredState(GetDlgItem(hdlg, IDOK_ST), true);
			break;
		default:
			break;
		}		
		return 0;
	}
	case WM_INITDIALOG:		//Read settings
	{
		if (ST.MD5)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD5), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD5), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.MD2)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD2), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD2), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.MD4)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD4), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_MD4), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.SHA1)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA1), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA1), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.SHA224)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA224), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA224), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.SHA256)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA256), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA256), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.SHA384)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA384), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA384), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.SHA512)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA512), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHA512), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.CRC32)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_CRC32), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_CRC32), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.CRC16)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_CRC16), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_CRC16), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.time)
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_TIME), BM_SETCHECK, BST_CHECKED, NULL);
		else
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_TIME), BM_SETCHECK, BST_UNCHECKED, NULL);

		if (ST.UseReg || ST.ShellMenu)
		{
			SendMessage(GetDlgItem(hdlg, IDC_RADIO_ENREG), BM_SETCHECK, BST_CHECKED, NULL);
			EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), true);
			EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), true);
			if (ST.singleinstance)
				SendMessage(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), BM_SETCHECK, BST_CHECKED, NULL);
			else
				SendMessage(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), BM_SETCHECK, BST_UNCHECKED, NULL);
			if (ST.ShellMenu)
				SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), BM_SETCHECK, BST_CHECKED, NULL);
			else
				SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), BM_SETCHECK, BST_UNCHECKED, NULL);
		}
		else
		{
			SendMessage(GetDlgItem(hdlg, IDC_RADIO_DISREG), BM_SETCHECK, BST_CHECKED, NULL);
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), BM_SETCHECK, BST_UNCHECKED, NULL);
			SendMessage(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), BM_SETCHECK, BST_UNCHECKED, NULL);
			EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SINGLEINS), false);
			EnableWindow(GetDlgItem(hdlg, IDC_CHECK_SHELLMENU), false);
		}

		switch (ST.CharEncoding)
		{
		case Encode_ANSI:
			SendMessage(GetDlgItem(hdlg, IDC_RADIO_ANSI), BM_SETCHECK, BST_CHECKED, NULL);
			break;
		case Encode_UTF8:
			SendMessage(GetDlgItem(hdlg, IDC_RADIO_UTF8), BM_SETCHECK, BST_CHECKED, NULL);
			break;
		default:
			SendMessage(GetDlgItem(hdlg, IDC_RADIO_UNICODE), BM_SETCHECK, BST_CHECKED, NULL);
			break;
		}
		return 0;
	}
	}
	return (INT_PTR)FALSE;
}

// About window Proc..
INT_PTR CALLBACK DlgAboutProc(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	
	switch (msg)
	{
	case WM_SYSCOMMAND:
		if (wParam == SC_CLOSE)
		{
			DestroyWindow(hdlg);
		}
		return 0;

	case WM_COMMAND:
	{
		if (LOWORD(wParam) == IDOK)
		{
			DestroyWindow(hdlg);
		}
		return 0;
	}
	case WM_INITDIALOG:
	{
		hWnddlgLOGO = CreateWindow(L"Static", L"", SS_ICON| WS_CHILD | WS_OVERLAPPED | WS_VISIBLE,
			270, 15, 128, 128, hdlg, (HMENU)LOGO_dlgwin, hInst, NULL);		
		DlgLOGO = (HICON)LoadImage(hInst, (LPCTSTR)IDI_ICON1, IMAGE_ICON, 128, 128, LR_SHARED);

		//From MSDN:	In version 6 of the Microsoft Win32 controls, 
		//				a bitmap passed to a static control using the STM_SETIMAGE 
		//				message was the same bitmap returned by a subsequent STM_SETIMAGE message. 
		//				The client is responsible to delete any bitmap sent to a static control.
		DestroyIcon((HICON)SendMessage(hWnddlgLOGO, STM_SETIMAGE, IMAGE_ICON,(LPARAM) DlgLOGO));
		return 0;
	}
	case WM_NOTIFY:
		// Don't know why, the example code from MSDN results in endless pop up windows... Only this works!
		if (((LPNMHDR)lParam)->idFrom==IDC_SYSLINK1)
		{
			if (((LPNMHDR)lParam)->code == NM_CLICK)
			{
				ShellExecute(NULL, L"open", L"http://www.weijiehuang.com/hashme", NULL, NULL, SW_SHOWNORMAL);		//If link was hit, open it.
			}			
		}
		break;
	}
	return (INT_PTR)FALSE;
}


//
// Function: DropHandelThread(LPVOID wParam)
//
// Purpose: Handle file on-window drop action
//
//
DWORD WINAPI DropHandelThread(LPVOID wParam)
{	
	int TotalNumberOfFiles = DragQueryFile((HDROP)wParam, 0xFFFFFFFF, NULL, 0);		//total number of files that user dropped
	PB.TotalFileToProcess = TotalNumberOfFiles;										//save this value in global ProgressStrcure
	PB.szFilepath = new TCHAR*[TotalNumberOfFiles];
	PB.szPrefixedFilepath = new TCHAR*[TotalNumberOfFiles];	
	PB.FileSize = new uint64_t[TotalNumberOfFiles];
	PB.szFileSizeText = new TCHAR*[TotalNumberOfFiles];

	//// Check how user want result to be output
	//if (SendMessage(hWndUCButton, BM_GETCHECK, NULL, NULL) == BST_CHECKED)
	//	ST.LetterCase = true;
	//else
	//	ST.LetterCase = false;

	//First sum up the size, initialize and write file name. prefixed file nanme table.
	for (int i = 0; i < TotalNumberOfFiles; i++)
	{
		int namebufferlen = DragQueryFile((HDROP)wParam, i, NULL, 0) + 1;
		int prefix_namebufferlen = namebufferlen + 4;
		PB.szFilepath[i] = new TCHAR[namebufferlen];
		PB.szPrefixedFilepath[i] = new TCHAR[prefix_namebufferlen];
		PB.szFileSizeText[i] = new TCHAR[FileSizeBufferLen];
		
		DragQueryFile((HDROP)wParam, i, PB.szFilepath[i], namebufferlen);
		Link2String(FileNamePrefix, PB.szFilepath[i], PB.szPrefixedFilepath[i], prefix_namebufferlen, 0);
		HANDLE hFile = CreateFile(PB.szPrefixedFilepath[i], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			FormatFileErrorOutput(OUTPUT_TEXT_BUFFER, PB.szFilepath[i]);
			PB.FileSize[i] = 0;
			SendMessage(hWndOutText, WM_SETTEXT, NULL, (LPARAM)OUTPUT_TEXT_BUFFER);
			SendMessage(hWndOutText, WM_VSCROLL, SB_BOTTOM, NULL);					
		}
		else
		{
			SendMessage(hWndPB, PBM_SETPOS, 2, 0);
			GetFileSizeEx(hFile, &OriFileLengh);
			PB.FileSize[i] = OriFileLengh.QuadPart;
			PB.TotalBytesToProcess += OriFileLengh.QuadPart;					
		}		
		_ui64tow_s(PB.FileSize[i], PB.szFileSizeText[i], FileSizeBufferLen, 10);
		CloseHandle(hFile);
	}
	PB.Checker = PB.TotalBytesToProcess / 50;

	//Read and process file
	HashmeFileProcess(&PB, &ST);
	return 0;
}


//
// Function: StartHandelThread(LPVOID wParam)
//
// Purpose: Handle right click HashME from system menu
//
DWORD WINAPI StartHandelThread(LPVOID wParam)
{
	ProgressStrcure* PBs = (ProgressStrcure*)wParam;
	HashmeFileProcess(PBs, &ST);
	return 0;
}

//
// Function: HashME_Mem()
//
// Purpose: Read and decode the text in Input_textbox and store in memery. Then call hash functions to solve hash value and output
//
//
void HashME_Mem()
{
	dwTimeBegin = GetTickCount();
	unsigned char *FormatedTextMemBlock = NULL;
	size_t MemCubeLen = 0;
	TCHAR *szInputText = NULL;
	size_t InputTextLen = 0;

	//if (SendMessage(hWndUCButton, BM_GETCHECK, NULL, NULL) == BST_CHECKED)
	//	ST.LetterCase = true;
	//else
	//	ST.LetterCase = false;

	SendMessage(hWndPB, PBM_SETPOS, 0, 0);
	InputTextLen = SendMessage((HWND)hWndInText, WM_GETTEXTLENGTH, (WPARAM)NULL, (LPARAM)NULL);		//Obtain the length of text (not include NULL) to be read
	szInputText = new TCHAR[InputTextLen + 1];														//Buffer, +1 for the ending NULL
	SendMessage(hWndInText, WM_GETTEXT, (WPARAM)(InputTextLen + 1), (LPARAM)szInputText);			//Read text from input textbox, unicode text, include NULL already
	FormatedTextMemBlock = new unsigned char[4 * InputTextLen + 1];									//Buffer for decode text, *4 for worst situation, +1 for ending NULL
	MemCubeLen = FormatTextToMemCube(szInputText, FormatedTextMemBlock, 4 * InputTextLen + 1, ST.CharEncoding);		//Decode, return unsigned char[]	
	if (ST.MD5)
	{
		md5_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);											//MD5, return is unsigned char[]			
		uCharToHexStringFormat(ctx_mem.MD5_result, ctx_mem.MD5_HexResult_Output, MD5_HASH_SIZE, MD5_HASH_RESULT_TEXT_SIZE, ST.LetterCase);							//Transfer unsigned char[] to 0x Hex format for output
	}
	if (ST.MD2)
	{
		md2_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.MD2_result, ctx_mem.MD2_HexResult_Output, MD2_HASH_SIZE, MD2_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.MD4)
	{
		md4_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.MD4_result, ctx_mem.MD4_HexResult_Output, MD4_HASH_SIZE, MD4_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.SHA1)
	{
		sha1_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.SHA1_result, ctx_mem.SHA1_HexResult_Output, SHA1_HASH_SIZE, SHA1_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.SHA224)
	{
		sha224_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.SHA224_result, ctx_mem.SHA224_HexResult_Output, SHA224_HASH_SIZE, SHA224_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.SHA256)
	{
		sha256_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.SHA256_result, ctx_mem.SHA256_HexResult_Output, SHA256_HASH_SIZE, SHA256_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.SHA384)
	{
		sha384_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.SHA384_result, ctx_mem.SHA384_HexResult_Output, SHA384_HASH_SIZE, SHA384_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.SHA512)
	{
		sha512_MemBlock(FormatedTextMemBlock, MemCubeLen, &ctx_mem);
		uCharToHexStringFormat(ctx_mem.SHA512_result, ctx_mem.SHA512_HexResult_Output, SHA512_HASH_SIZE, SHA512_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	if (ST.CRC32|| ST.CRC16)
	{
		CRC_Mem(FormatedTextMemBlock, MemCubeLen, &ST, &ctx_mem);
		uIntToHexStringFormat(ctx_mem.CRC32_hash_, ctx_mem.CRC32_HexResult_Output, CRC32_HASH_SIZE, CRC32_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
		uIntToHexStringFormat(ctx_mem.CRC16_hash_, ctx_mem.CRC16_HexResult_Output, CRC16_HASH_SIZE, CRC16_HASH_RESULT_TEXT_SIZE, ST.LetterCase);
	}
	
	FormatMemResultOutput(OUTPUT_TEXT_BUFFER, szInputText, &ctx_mem, &ST);
	SendMessage(hWndOutText, WM_SETTEXT, NULL, (LPARAM)OUTPUT_TEXT_BUFFER);				//Output to output textbox	
	SendMessage(hWndInText, WM_SETTEXT, NULL, (LPARAM)L"");							//Clear input box
	dwTimeEnd = GetTickCount();
	FormatInfoLableFinishOutput(OUTPUT_LABLE_BUFFER, (uint32_t)(dwTimeEnd - dwTimeBegin));
	SendMessage(hWndLable, WM_SETTEXT, NULL, (LPARAM)OUTPUT_LABLE_BUFFER);
	OUTPUT_LABLE_BUFFER[0] = NULL;
	delete[] szInputText;
	delete[] FormatedTextMemBlock;
	SendMessage(hWndPB, PBM_SETPOS, 100, 0);
}


void HashmeFileProcess(ProgressStrcure* PB, Settings* ST)
{
	// Set beginning time
	dwTimeBegin = GetTickCount();
	// initialization, disable buttons to avoid user change parameters during processing
	WORKING = true;
	STOP = false;
	{
		EnableWindow(hWndExcButton, false);
		EnableWindow(hWndSettingButton, false);
		EnableWindow(hWndClearButton, false);
		EnableWindow(hWndInText, false);
		EnableWindow(hWndUCButton, false);
		EnableWindow(hWndLCButton, false);
	}

	for (uint32_t i = 0; i < PB->TotalFileToProcess; i++)
	{	
		HANDLE hFile = CreateFile(PB->szPrefixedFilepath[i], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			PB->FileUnderProcessing = i + 1;
			_wsplitpath_s(PB->szFilepath[i], NULL, 0, NULL, 0, tempFilename, _MAX_FNAME, tempFileextn, _MAX_EXT);
			Link2String(tempFilename, tempFileextn, PB->FilenameUnderProcessing, _MAX_FNAME + _MAX_EXT, 0);
			if (!File_Hash(hFile, PB->FileSize[i], hWndPB, hWndLable, PB, &ctx, ST, &STOP))
			{
				FormatInformationOutput(OUTPUT_TEXT_BUFFER, Process_stopped_text);
				SendMessage(hWndOutText, WM_SETTEXT, NULL, (LPARAM)OUTPUT_TEXT_BUFFER);
				CloseHandle(hFile);
				break;
			}
			FormatFileResultOutput(OUTPUT_TEXT_BUFFER, PB->szFilepath[i], PB->szFileSizeText[i], &ctx, ST);
			SendMessage(hWndOutText, WM_SETTEXT, NULL, (LPARAM)OUTPUT_TEXT_BUFFER);
			SendMessage(hWndOutText, WM_VSCROLL, SB_BOTTOM, NULL);
		}
		CloseHandle(hFile);
	}
	//File process finished
	dwTimeEnd = GetTickCount();
	if (STOP)
	{
		SendMessage(hWndPB, PBM_SETPOS, 0, 0);
		SendMessage(hWndOutText, WM_VSCROLL, SB_BOTTOM, NULL);
		wcscat_s(OUTPUT_LABLE_BUFFER, 60, Info_lable_caption);
	}
	else
	{
		FormatInfoLableFinishOutput(OUTPUT_LABLE_BUFFER, dwTimeEnd - dwTimeBegin);
		SendMessage(hWndPB, PBM_SETPOS, 100, 0);
	}
	SendMessage(hWndLable, WM_SETTEXT, NULL, (LPARAM)OUTPUT_LABLE_BUFFER);
	OUTPUT_LABLE_BUFFER[0] = NULL;
	{
		EnableWindow(hWndExcButton, true);
		EnableWindow(hWndSettingButton, true);
		EnableWindow(hWndClearButton, true);
		EnableWindow(hWndInText, true);
		EnableWindow(hWndUCButton, true);
		EnableWindow(hWndLCButton, true);
	}
	for (uint32_t i = 0; i < PB->TotalFileToProcess; i++)
	{
		delete[] PB->szFilepath[i];
		delete[] PB->szFileSizeText[i];
		delete[] PB->szPrefixedFilepath[i];
	}
	delete[] PB->szFilepath;
	delete[] PB->szPrefixedFilepath;
	delete[] PB->FileSize;
	delete[] PB->szFileSizeText;
	WORKING = false;
}


void InitHashME(HWND hWnd, Settings *ST)
{
	const TCHAR* fontName = _T("MS Shell Dlg");
	const long nFontSize9 = 9;
	const long nFontSize8 = 8;
	HDC hdc = GetDC(hWnd);

	LOGFONT logFont9 = { 0 };
	logFont9.lfHeight = -MulDiv(nFontSize9, GetDeviceCaps(hdc, LOGPIXELSY), 72);
	logFont9.lfWeight = FW_NORMAL;
	_tcscpy_s(logFont9.lfFaceName, fontName);
	hFont9 = CreateFontIndirect(&logFont9);

	LOGFONT logFont8 = { 0 };
	logFont8.lfHeight = -MulDiv(nFontSize8, GetDeviceCaps(hdc, LOGPIXELSY), 72);
	logFont8.lfWeight = FW_NORMAL;
	_tcscpy_s(logFont8.lfFaceName, fontName);
	hFont8 = CreateFontIndirect(&logFont8);

	ReleaseDC(hWnd, hdc);

	int scrWidth, scrHeight;
	RECT rect;
	//Get screen size
	scrWidth = GetSystemMetrics(SM_CXSCREEN);
	scrHeight = GetSystemMetrics(SM_CYSCREEN);
	//Get window size
	GetWindowRect(hWnd, &rect);
	//Calclulate center position
	rect.left = (scrWidth - rect.right) / 2;
	rect.top = (scrHeight - rect.bottom) / 2;
	//Set position
	SetWindowPos(hWnd, HWND_TOP, rect.left, rect.top, rect.right, rect.bottom, SWP_SHOWWINDOW);

	hWndExcButton = CreateWindow(L"Button", L"HashME", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		520, 10, 50, 20, hWnd, (HMENU)Execute_Button, hInst, NULL);
	SendMessage(hWndExcButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndClearButton = CreateWindow(L"Button", Clear_botton_caption, WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		10, FunctionButton_Y, 80, 25, hWnd, (HMENU)Clear_Button, hInst, NULL);
	SendMessage(hWndClearButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndStopButton = CreateWindow(L"Button", Stop_botton_caption, WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		110, FunctionButton_Y, 80, 25, hWnd, (HMENU)Stop_Button, hInst, NULL);
	SendMessage(hWndStopButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndSettingButton = CreateWindow(L"Button", Setting_botton_caption, WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		210, FunctionButton_Y, 80, 25, hWnd, (HMENU)Setting_Button, hInst, NULL);
	SendMessage(hWndSettingButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndAboutButton = CreateWindow(L"Button", About_botton_caption, WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
		310, FunctionButton_Y, 80, 25, hWnd, (HMENU)About_Button, hInst, NULL);
	SendMessage(hWndAboutButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndInText = CreateWindowEx(WS_EX_CLIENTEDGE | WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, L"EDIT", L"", ES_LEFT | ES_AUTOHSCROLL | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE,
		10, 10, 500, 20, hWnd, (HMENU)Input_Editbox, hInst, NULL);
	SendMessage(hWndInText, WM_SETFONT, (WPARAM)hFont9, TRUE);
	OldEditProc = (WNDPROC)SetWindowLongPtr(hWndInText, GWLP_WNDPROC, (LONG_PTR)EditSubProc);

	hWndOutText = CreateWindowEx(WS_EX_CLIENTEDGE | WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, L"EDIT", L"", ES_LEFT | ES_READONLY | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE,
		10, 40, 560, 210, hWnd, (HMENU)Output_Editbox, hInst, NULL);
	SendMessage(hWndOutText, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndPB = CreateWindowEx(WS_EX_LEFT | WS_EX_LTRREADING | WS_EX_RIGHTSCROLLBAR, PROGRESS_CLASS, NULL, WS_CHILD | WS_VISIBLE,
		10, 295, 560, 15, hWnd, (HMENU)Progress_Bar, hInst, NULL);

	hWndLable = CreateWindow(L"Static", Info_lable_caption, SS_LEFT | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE,
		10, 315, 560, 20, hWnd, (HMENU)Info_Lable, hInst, NULL);
	SendMessage(hWndLable, WM_SETFONT, (WPARAM)hFont9, TRUE);

	hWndUCButton = CreateWindow(L"Button", Ucase_radbotton_caption, WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
		410, FunctionButton_Y + 5, 80, 15, hWnd, (HMENU)UCase_RadButton, hInst, NULL);
	SendMessage(hWndUCButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	hWndLCButton = CreateWindow(L"Button", Lcase_radbotton_caption, WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
		490, FunctionButton_Y +5, 80, 15, hWnd, (HMENU)LCase_RadButton, hInst, NULL);
	SendMessage(hWndLCButton, WM_SETFONT, (WPARAM)hFont8, TRUE);

	if (ST->LetterCase == true)
		SendMessage(hWndUCButton, BM_SETCHECK, BST_CHECKED, NULL);
	else
		SendMessage(hWndLCButton, BM_SETCHECK, BST_CHECKED, NULL);
}

void RegRead(Settings *ST)
{
	HKEY SettingKey;
	HKEY ShellKey;
	HKEY CurrentUserKey;
	DWORD dwType = REG_DWORD;
	DWORD value;
	DWORD value_length = sizeof(DWORD);

	RegOpenCurrentUser(KEY_READ | KEY_WOW64_64KEY, &CurrentUserKey);
	if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CLASSES_ROOT, L"\\*\\shell\\HashME", 0, KEY_READ | KEY_WOW64_64KEY, &ShellKey))
	{
		ST->ShellMenu = true;
	}
	else
	{
		ST->ShellMenu = false;
	}
	if (ERROR_SUCCESS == RegOpenKeyEx(CurrentUserKey, L"SOFTWARE\\HashME\\Setting", 0, KEY_READ | KEY_WOW64_64KEY, &SettingKey))
	{
		ST->UseReg = true;
		value = 0;
		RegQueryValueEx(SettingKey, L"Time", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->time = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"MD2", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->MD2 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"MD4", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->MD4 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"MD5", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->MD5 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"SHA1", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->SHA1 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"SHA224", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->SHA224 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"SHA256", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->SHA256 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"SHA384", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->SHA384 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"SHA512", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->SHA512 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"CRC32", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->CRC32 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"CRC16", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->CRC16 = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"CharEncoding", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->CharEncoding = (int)value;
		value = 0;
		RegQueryValueEx(SettingKey, L"LetterCase", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->LetterCase = value != 0;
		value = 0;
		RegQueryValueEx(SettingKey, L"singleinstance", NULL, &dwType, (LPBYTE)&value, &value_length);
		ST->singleinstance = value != 0;
	}
	else
	{
		ST->UseReg = false;		
	}	
	RegCloseKey(ShellKey);
	RegCloseKey(SettingKey);
}

/*
Error code:
		0 : Normal
		1 : Creat or open reg fail
		2 : Save settings fail
		3 : Save shell menu fail
		4 : Delete settings fail
		5 : Delete shell menu fail
		6 : Other

Para code:
		-2: delete all keys
		-1: delete shell keys
		1: Set shell menu
		2: Set settings, lettle case
		3: Only set lettle case
*/
int RegWrite(Settings *ST, int para)
{
	HKEY SettingKey;
	HKEY ShellKey;
	HKEY CommandKey;
	HKEY CurrentUserKey;
	DWORD reShell, reSetting;
	DWORD value;
	DWORD value_length = sizeof(DWORD);
	TCHAR* MenuText = L"HashME";
	TCHAR* Commandtext = NULL;
	int result = 0;
	int resShell, resSetting;

	RegOpenCurrentUser(KEY_ALL_ACCESS | KEY_WOW64_64KEY, &CurrentUserKey);
	if (para < 0)	// Delete keys
	{
		resShell = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"*\\shell\\HashME", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &ShellKey);
		if (resShell != ERROR_FILE_NOT_FOUND)
		{
			if (ERROR_SUCCESS == resShell)
			{
				if (ERROR_SUCCESS != RegDeleteTree(ShellKey, NULL))
					result = 5;
				if (ERROR_SUCCESS != RegDeleteKeyEx(HKEY_CLASSES_ROOT, L"*\\shell\\HashME", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0))
					result = 5;
			}
			else
				result = 1;
		}
		resSetting = RegOpenKeyEx(CurrentUserKey, L"SOFTWARE\\HashME", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &SettingKey);
		if ((resSetting != ERROR_FILE_NOT_FOUND) && (para == -2))
		{
			if (ERROR_SUCCESS == resSetting)
			{
				if (ERROR_SUCCESS != RegDeleteTree(SettingKey, NULL))
					result = 4;
				if (ERROR_SUCCESS != RegDeleteKeyEx(CurrentUserKey, L"SOFTWARE\\HashME", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0))
					result = 4;
			}
			else
				result = 1;
		}
	}
	else
	{
		RegCreateKeyEx(HKEY_CLASSES_ROOT, L"*\\shell\\HashME", 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &ShellKey, &reShell);
		RegCreateKeyEx(CurrentUserKey, L"SOFTWARE\\HashME\\Setting", 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &SettingKey, &reSetting);
		switch (para)
		{			
			//Creat, update shell keys
		case 1:			
			if (reSetting == REG_CREATED_NEW_KEY || reSetting == REG_OPENED_EXISTING_KEY)
			{
				int CPathlen = _tcslen(CurrentPath);
				if (ERROR_SUCCESS != RegSetValueEx(ShellKey, NULL, 0, REG_SZ, (const BYTE*)MenuText, 2 * (CPathlen + 1)))
					result = 3;
				if (ERROR_SUCCESS != RegSetValueEx(ShellKey, TEXT("Icon"), 0, REG_SZ, (const BYTE*)CurrentPath, 2 * (CPathlen + 1)))
					result = 3;
				Commandtext = new TCHAR[CPathlen + 8];
				Commandtext[0] = L'\"';
				Link2String(CurrentPath, L"\" \"%1\"", Commandtext, CPathlen + 8, 1);
				RegCreateKeyEx(HKEY_CLASSES_ROOT, L"*\\shell\\HashME\\Command", 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &CommandKey, &reSetting);
				if (reSetting == REG_CREATED_NEW_KEY || reSetting == REG_OPENED_EXISTING_KEY)
				{
					if (ERROR_SUCCESS != RegSetValueEx(CommandKey, NULL, 0, REG_SZ, (const BYTE*)Commandtext, 2 * (CPathlen + 9)))
						result = 3;
				}
				else
					result = 1;
			}
			else
				result = 1;
			RegCloseKey(CommandKey);
			break;

			//Creat, update setting keys
		case 2:			
			if (reShell == REG_CREATED_NEW_KEY || reShell == REG_OPENED_EXISTING_KEY)
			{
				value = ST->time;
				RegSetValueEx(SettingKey, TEXT("Time"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->MD2;
				RegSetValueEx(SettingKey, TEXT("MD2"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->MD4;
				RegSetValueEx(SettingKey, TEXT("MD4"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->MD5;
				RegSetValueEx(SettingKey, TEXT("MD5"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->SHA1;
				RegSetValueEx(SettingKey, TEXT("SHA1"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->SHA224;
				RegSetValueEx(SettingKey, TEXT("SHA224"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->SHA256;
				RegSetValueEx(SettingKey, TEXT("SHA256"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->SHA384;
				RegSetValueEx(SettingKey, TEXT("SHA384"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->SHA512;
				RegSetValueEx(SettingKey, TEXT("SHA512"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->CRC16;
				RegSetValueEx(SettingKey, TEXT("CRC16"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->CRC32;
				RegSetValueEx(SettingKey, TEXT("CRC32"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->CharEncoding;
				RegSetValueEx(SettingKey, TEXT("CharEncoding"), 0, REG_DWORD, (const BYTE*)&value, value_length);
				value = ST->singleinstance;
				RegSetValueEx(SettingKey, TEXT("singleinstance"), 0, REG_DWORD, (const BYTE*)&value, value_length);				
			}
			else
				result = 1;
			//No break needed

			//Update letter case only
		case 3:			
			if (reShell == REG_CREATED_NEW_KEY || reShell == REG_OPENED_EXISTING_KEY)
			{
				value = ST->LetterCase;
				if (ERROR_SUCCESS != RegSetValueEx(SettingKey, TEXT("LetterCase"), 0, REG_DWORD, (const BYTE*)&value, value_length))
					result = 2;
			}
			else
				result = 1;
			break;
		default:
			result = 6;
			break;
		}
	}
	RegCloseKey(SettingKey);
	RegCloseKey(ShellKey);
	return result;
}