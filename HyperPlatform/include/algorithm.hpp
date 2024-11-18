#pragma once
#include"global.hpp"

namespace std
{
	template <class InputIterator,typename T>
	InputIterator find(InputIterator first, InputIterator last, const T& value)
	{
		//
		// 一定得是*first != value，而不是value != *first
		//
		while (first != last && *first != value)
			first++;

		return first;
	}






































}