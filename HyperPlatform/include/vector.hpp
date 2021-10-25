/*
Copyright (c) 2021-x	 https://github.com/helloobaby/KernelModeSTL
*/

#pragma once
#include"global.hpp"

/***

*Revision History:
	2021/8/4	add pop_back()、front()、back()
	2021/8/5	add	erase()、resize()、clear()、		
****/

namespace std {



	template <typename T>
	class vector
	{
	public:
		using value_type = T;
		using size_type = size_t;
		using pointer = value_type*;
		using iterator = value_type*;
		using const_iterator = const iterator;
		using reference = value_type&;

		vector() : start(0), finish(0), end_of_storage(0) {}
		~vector();

		iterator begin()const { return start; }
		iterator end()const { return finish; }

		size_type size() const { return (size_type)(end() - begin()); }

		bool empty() const { return begin() == end(); }

		void push_back(const T& x);
		void pop_back() { --finish; destroy(finish); }
		void insert_aux(iterator position, const T& x);
		reference front(){ return *begin(); };
		reference back() { return *(end() - 1); };
		iterator erase(iterator position)
		{
			//这行代码其实可以用在list上面，因为list他是直接删除的，原始迭代器必然失效，但是vector不会，因为是线性的
			//iterator next = position++;
			
			/***
			*这里侯捷的STL源码剖析p117的erase方法好像是有勘误的
			*他只判断了要删除的位置和可用空间的最后位置，不因该是当前使用空间的最后位置？
			***/
			if (position >= finish)	//never return
				ExRaiseAccessViolation();
			
			if (position + 1 == finish)
			{
				--finish;
				destroy(finish);
				return position;
			}
			else
			{
				auto tmp = position;
				while (position < finish - 1)
				{
					destroy(position);
					auto next = position + 1;
					/*
						这里不需要析构next，因为我们刚开始用的是new[]，编译器记得我们总共多少个对象，
						析构的时候是delete[]，这样编译器确保我们刚开始分配的所有对象都会被析构，如果这里
						要析构的话，vector的析构函数就得自己从start到finish释放对象，而不能delete[]
					*/
					construct(position, *next);
					destory(next);
					position++;

				}
				--finish;
				return tmp;
			}
		}
		iterator erase(iterator first, iterator last)
		{
			if (last > finish)
				ExRaiseAccessViolation();
			auto tmp = first;
			while ((first++) != last)
			{
				destroy(first - 1);
			}
			first = tmp;
			if (last < finish)
			{
				while ((last++) != finish)
				{
					construct(first, *(last - 1));
					destroy(last - 1);
					first++;
				}
			}
			finish = first;
		}
		size_t capacity()const 
		{
#if 0
			DbgBreakPoint();
#endif
			//
			//两个指针相减，编译器会自动用地址差值/对象大小，获得准确的对象数量
			//
			return size_type(end_of_storage - start); 
		}
		reference operator[](size_type n) { return *(begin() + n); }
		
		/*
		*
		void insert(iterator postion, size_type n, const T& x)
		{
		
		}
		*/
		void resize(size_type new_size)
		{
#if 0
			DbgBreakPoint();
#endif
			if (new_size < size()) {
				destroy<vector<T>>(begin() + new_size, finish);
				finish = begin() + new_size;
			}
			else if(new_size > size())
			{
				//空间扩大要引起空间的重新分配
				
				//保存原来的内存地址
				auto tmp = new T[new_size];
				auto new_start = tmp;
				auto old_start = start;
				while (start != finish) {
					construct(tmp, *start);
					destroy(start);
					start++;
					tmp++;
				}
				if (old_start) {

					if (std::is_pod<T>::value)
						deallocate((size_t*)old_start);
					else
						deallocate((size_t*)old_start - 1);
				}
				start = new_start;
				finish = tmp;
				end_of_storage = start + new_size;

			}
		}
	private:
		//[this]
		iterator start;		//表示目前使用空间的头
		//[this+8]
		iterator finish;	//表示目前使用空间的尾
		//[this+16]
		iterator end_of_storage;//表示目前可用空间的尾

	};


	template<typename T>
	void vector<T>::push_back(const T& x)
	{
		if (finish < end_of_storage) {
			construct(finish, x);
			++finish;
		}
		else
		{
			insert_aux(end(), x);
		}
	}

	template<typename T>
	void vector<T>::insert_aux(vector<T>::iterator position, const T& x)
	{
		UNREFERENCED_PARAMETER(position);
		if (finish < end_of_storage)
		{
			construct(finish, x);
			++finish;
		}
		else {   
			
			const size_type old_size = size();
			const size_type new_size = (!old_size) ? 1 : old_size * 2;

			iterator new_start = new T[new_size];//编译器实现为sizeof(T) * new_size,实际分配会加size_t个字节
			iterator new_finish = new_start;

			if (start != 0) {//原先vector中存有数据，将旧数据拷贝到新vector中
				auto tmp = start;
				while (start < finish) {
					construct(new_finish, *start);
					new_finish++;
					start->~T();
					start++;
				}
				//数据移动完之后记得释放
				if (std::is_pod<T>::value)
					deallocate((size_t*)tmp);
				else
					deallocate((size_t*)tmp - 1);
			}
			
			end_of_storage = new_start + new_size;
			construct(new_finish, x);
			new_finish++;
			start = new_start;
			finish = new_finish;
		}

	}

	template<typename T>
	vector<T>::~vector()
	{
		if (!start)
			return;

		/*
			编译器会替我们逐个start->~T();
		*/
		//delete[] start;
		destroy<vector<T>>(start, finish);
		
		if (std::is_pod<T>::value)
			deallocate((size_t*)start);
		else
			deallocate((size_t*)start - 1);
	}

}

static_assert(sizeof(std::vector<int>) == 0x18);
