#include"string.hpp"

namespace std
{
		string::~string() {
			delete[] m_src;
		}

		string::string(const char* to_copy)
		{
			if (!to_copy)
			{
				//下面注释代码会造成一字节的内存泄露
				//m_src = new char[1];
				//m_src[0] = '\0';
				m_size = 0;
			}
			else
			{
				m_size = strlen(to_copy);
				m_src = new char[m_size + 1];
				strcpy(m_src, to_copy);
			}
		}

		/*
		vector<string> v;
		v.push_back("hello world\n");
		*/
		string::string(const string& str)
		{
			//move? copy?
			m_size = strlen(str.c_str());
			m_src = new char[m_size + 1];
			strcpy(m_src, str.c_str());
		}

		string& string::operator=(const string& str)
		{
			delete[] m_src;
			m_src = new char[str.size()];
			strcpy(m_src, str.c_str());
			return *this;
		}

		const char* string::c_str() const
		{
			return m_src;
		}
		const string::size_type string::size() const
		{
			return m_size;
		}

		string::reference string::operator[](size_t index)
		{
			if (m_size == 0)
				ExRaiseAccessViolation();

			return m_src[index];
		}

		//------------------wstring的实现

	
		wstring::~wstring()
		{
			delete[] m_src;
		}

		wstring::wstring(const wchar_t* to_copy)
		{
			if (!to_copy)
			{
				//下面注释代码会造成一字节的内存泄露
				//m_src = new char[1];
				//m_src[0] = '\0';
				m_size = 0;
			}
			else
			{
				m_size = wcslen(to_copy);
				m_src = new wchar_t[m_size + 1];
				wcscpy(m_src, to_copy);
			}
		}

		wstring::wstring(const wstring& str)
		{
			m_size = wcslen(str.c_str());
			m_src = new wchar_t[m_size + 1];
			wcscpy(m_src, str.c_str());
		}

		wstring& wstring::operator=(const wstring& str)
		{
			delete[] m_src;
			m_src = new wchar_t[str.size()];
			wcscpy(m_src, str.c_str());
			return *this;
		}

		wstring::reference wstring::operator[](size_t index)
		{
			if (m_size == 0)
				ExRaiseAccessViolation();

			return m_src[index];
		}

		const string::size_type wstring::size() const
		{
			return m_size;
		}

		const wchar_t* wstring::c_str() const
		{
			return m_src;;
		}


}