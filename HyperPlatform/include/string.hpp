/*
Copyright (c) 2021-x	 https://github.com/helloobaby/KernelModeSTL
*/

#pragma once 
#include"global.hpp"

namespace std
{
	class string
	{
	public:
		using size_type = size_t;
		using value_type = char;
		using pointer = value_type*;
		using iterator = value_type*;
		using const_iterator = const iterator;
		using reference = value_type&;

		~string();

		string(const char* to_copy = nullptr);
		string(const string& str);
		string& operator=(const string& str);

		iterator begin() { return m_src; }
		iterator end() { return m_src + m_size; }

		reference operator[](size_t index);

		bool empty() { return m_size ? 0 : 1; }

		const size_type size() const;

		const char* c_str() const;
	private:
		//[this]
		char* m_src = nullptr;
		//[this+8]
		size_type m_size = 0; 
	};

	class wstring
	{
	public:
		using size_type = size_t;
		using value_type = wchar_t;
		using pointer = value_type*;
		using iterator = value_type*;
		using const_iterator = const iterator;
		using reference = value_type&;
		~wstring();

		wstring(const wchar_t* to_copy = nullptr);
		wstring(const wstring& str);
		wstring& operator=(const wstring& str);

		iterator begin() { return m_src; }
		iterator end() { return m_src + m_size; }

		reference operator[](size_t index);

		bool empty() { return m_size ? 0 : 1; }

		const size_type size() const;

		const wchar_t* c_str() const;
	private:
		wchar_t* m_src = nullptr;
		size_type m_size = 0;
	};

}

static_assert(sizeof(std::string) == 0x10);