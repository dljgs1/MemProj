#include<windows.h>
#include<Windows.h>
#include<stdlib.h>
#include<tlhelp32.h>
#include<Psapi.h>
#include<string>
#include<iostream>
#include<vector>
#include<fstream>

using namespace std;


/*


*/
using std::string;
using std::wstring;
using std::vector;

#pragma comment (lib,"Psapi.lib")
#pragma warning(disable:4996)  


//通过进程名获取进程号
DWORD GetProcessIdByName(TCHAR* lpName){
	//根据进程名获取进程ID,失败时返回0(System Idle Process) 
	DWORD dwProcessId;
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE){
		PROCESSENTRY32 ppe;
		ppe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &ppe)){
			if (strcmp(lpName, ppe.szExeFile) == 0){
				dwProcessId = ppe.th32ProcessID;
				CloseHandle(hSnapshot);
				return dwProcessId;
			}
			while (Process32Next(hSnapshot, &ppe)){//wcscmp
				if (strcmp(lpName, ppe.szExeFile) == 0){
					dwProcessId = ppe.th32ProcessID;
					CloseHandle(hSnapshot);
					return dwProcessId;
				}
			}
		}
		CloseHandle(hSnapshot);
	}
	return 0;
}




//枚举窗口
vector<HWND>hwnds;
BOOL CALLBACK EnumWindowsProc(
	HWND hwnd,
	LPARAM lParam){

	TCHAR caption[200];
	memset(caption, 0, sizeof(caption));
	::GetWindowText(hwnd, caption, 200);

	if (strcmp(caption, "")){
		cout << hwnds.size()<< ". " << caption << endl;
		hwnds.push_back(hwnd);
	}
	return TRUE;

}



/*内存检查类
成员函数说明：
构造函数：输入进程名或者窗口句柄构造
find_val：输入要找的变量值，存储结果
check_val：检查结果地址中的变量值，将变化的地址返回
modi_val：输入地址变量和新的值，进行修改
*/

class Mem_checker{
private:
	HANDLE hProc;
	DWORD oldway;
	vector<char*> addrs;//results

public:

	Mem_checker(HWND hwnd){
		DWORD pid;
		GetWindowThreadProcessId(hwnd, &pid);
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		cout << hProc << endl;
	}

	Mem_checker(LPTSTR name = "1.exe"){
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdByName(name));
		cout << hProc << endl;
	}

	int result_num(){
		return addrs.size();
	}

	bool find_val(int dst_val){
		int count = 0;
		unsigned long long base = 0x00;
		MEMORY_BASIC_INFORMATION mbi;
		DWORD fok = true;
		addrs = vector<char*>();

		while (fok){
			fok = VirtualQueryEx(hProc, (LPCVOID)base, &mbi, sizeof(mbi));
			if (mbi.State == MEM_COMMIT){
				int value;
				SIZE_T n = 1;
				VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldway);
				char*buff = new char[mbi.RegionSize];
				ReadProcessMemory(hProc, mbi.BaseAddress, buff, mbi.RegionSize, &n);
				
				for (int ad = 0; ad < mbi.RegionSize; ad += 4){
					int* ptr = (int*)(buff + ad);
					if (*ptr == dst_val){
						//cout << "find" <<(unsigned int)(buff + ad) << "\n";
						int val;
						SIZE_T n;
						ReadProcessMemory(hProc, (void*)((char*)mbi.BaseAddress+ad), &val, 4, &n);
						if (val != dst_val){
							cout << "error";
						}
						else{
							addrs.push_back((char*)mbi.BaseAddress + ad);
						}
					}
				}
				VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldway, &oldway);
				delete buff;
			}
			base += mbi.RegionSize;
		}
		cout << dst_val << "dst over" << addrs.size() << "\n";;
		if (addrs.size() > 0){
			return true;
		}
		else{
			return false;
		}
	}


	vector<char*> check_val(int dst_val){
		int val;
		int t=0, f=0;
		vector<char*>ptrs;
		for (auto&addr : addrs){
			SIZE_T n = 4;
			VirtualProtectEx(hProc, addr, 4, PAGE_READWRITE, &oldway);
			ReadProcessMemory(hProc, addr, &val, 4, &n);
			VirtualProtectEx(hProc, addr, 4, oldway, &oldway);
			if (val != dst_val){
				ptrs.push_back(addr);
			}
			else{
				t += 1;
			}
		}
		return ptrs;
		//cout << t << "t rate:" << (double)t / (t + f) << endl;
		//cout << f << "f rate:" << (double)f / (t + f) << endl;
	}


	void modi_val(char*addr, int val){
		SIZE_T n = 1;
		VirtualProtectEx(hProc, addr, 4, PAGE_READWRITE, &oldway);
		WriteProcessMemory(hProc, addr, &val, 4, &n);
		VirtualProtectEx(hProc, addr, 4, oldway, &oldway);
	}


};



int main(){
	int dst;
	Mem_checker ck;
	cout << "选择要check的进程（不选择合适编号如-1的话默认选测试进程1.exe）" << endl;
	EnumWindows(EnumWindowsProc, NULL);
	cin >> dst;
	if (dst < hwnds.size() && dst >= 0)
		ck = Mem_checker(hwnds[dst]);


	while (1){
		cout << "输入要检查的数值，在检测到后会持续监听，对于变化的变量地址给予记录:";
		cin >> dst;
		if (ck.find_val(dst)){
			cout << "对" << ck.result_num() << "个结果进行监听..." << endl;
			bool sflag = false;
			while (1){
				Sleep(1000);
				auto res = ck.check_val(dst);
				if (res.size()){
					cout << "以下地址发生了变化（保存至addr.txt）：" << endl;
					ofstream fout("addr.txt", ios::app);
					for (int i = 0; i < res.size(); i++){
						cout << i << ". " << static_cast<void*>(res[i]) << endl;
						fout << static_cast<void*>(res[i]) << endl;
					}
					while (1){
						cout << "输入地址序号进行修改（输入-1不修改）" << endl;
						int cho;
						cin >> cho;
						if (cho >= 0 && cho < res.size()){
							cout << "输入新的值" << endl;
							int val;
							cin >> val;
							ck.modi_val(res[cho], val);
							char c;
							cout << "是否继续修改？(y/n)";
							cin >> c;
							if (c != 'y')break;
						}
					}
					sflag = true;
				}
				if (sflag){
					char c;
					cout << "是否继续监听？(y/n)";
					cin >> c;
					if (c != 'y')
						break;
					sflag = false;
				}
			}
		}
		else{
			cout << "未找到该变量，重新输入" << endl;
			system("pause");
			system("cls");
		}
	}

	/*VirtualProtectEx();

	ReadProcessMemory();
	WriteProcessMemory();*/
	return 0;
}
//---255line---