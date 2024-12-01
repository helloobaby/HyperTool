#pragma once
#include "global.hpp"
#include "vector.hpp"

namespace std
{
	inline int prime_list_size = 20;
	inline unsigned long prime_list[]
	{
		53,97,193,389,769,
		1543,3079,6151,12289,24593,
		49157,98317,196613,393241,786433,
		1572869,3145739,6291469,12582917,25165843
	};

	template <typename key, typename value>
	struct _hashtable_node
	{
		// 因为只有下一个节点的指针
		// 以此封装的迭代器只支持前进操作，不支持后退，也没有逆向迭代器
		_hashtable_node* next;
		key k;
		value val;

	};


	template<typename key, typename value, typename HashFcn>
	struct __hashtable_iterator
	{
		using reference = value&;
		using pointer = value*;
		using node = _hashtable_node<key, value>;

		node* cur;

		__hashtable_iterator(node* n) { cur = n; }

		reference operator*()const { return cur->val; }


	};

	template<class key,
		class value,
		// type_traits.hpp提供一部分默认的哈希函数
		class HashFcn = std::hash<key>>
		class hashtable
	{
		using node = _hashtable_node<key, value>;
		using size_type = size_t;
		using iterator = __hashtable_iterator<key, value, HashFcn>;

	private:
	public:
		std::vector<node*> buckets;

		// 选择buckets的大小
		void initialize_buckets(size_type n)
		{
			auto next_size = [n]() {
				//返回大于n的最大质数
				for (auto prime : prime_list)
				{
					if (prime > n)
						return prime;
				}
				};
			buckets.resize(next_size());
		}

		// 默认构造函数
		hashtable()
		{
			initialize_buckets(20000);
		}

		// 表示最大支持的buckets是多少
		unsigned long max_buckets()
		{
			return prime_list[prime_list_size - 1];
		}

		// 确定某个obj该放哪个位置,返回下标(索引)
		size_t bkt_num(key obj)
		{
			return HashFcn()(obj) % buckets.capacity();
		}

		// 向hashtable中插入数据
		iterator insert(key k, value val)
		{
			//
			//算出这个数据落地点
			//
			const size_type n = bkt_num(k);
			node* first = buckets[n];
			if (!first)
			{
				//
				//落地点为空，直接写value
				//
				first = new node;
				first->val = val;
				first->k = k;
			}
			else
			{
				//哈希冲突了
				
			}

			return first;
		}

	};










