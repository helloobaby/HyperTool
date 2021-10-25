/*
Copyright (c) 2021-x	 https://github.com/helloobaby/KernelModeSTL
*/

/*
	std::is_pod好像在c++20要被弃用
*/
namespace std
{
	/*
	* 这个虽然能用，但是不满足c++标准用法
	template <typename T>
	constexpr bool is_pod()
	{
		return is_pod_type<T>::value;
	}
	*/


	template <typename T>
	struct is_pod
	{
		static const bool value = is_pod_type<T>::value;
		constexpr bool operator()()
		{
			return value;
		}
	};

	template <typename T>
	struct is_pod_type
	{
		static const bool value = false;
	};

	//
	// 要对c++所有POD类型全特化
	//


	template <>
	struct is_pod_type<char>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<signed char>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<unsigned char>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<short>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<unsigned short>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<int>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<unsigned int>
	{
		static const bool value = true;
	};


	template <>
	struct is_pod_type<long>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<unsigned long>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<float>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<double>
	{
		static const bool value = true;
	};

	template <>
	struct is_pod_type<long double>
	{
		static const bool value = true;
	};

	template<typename T>
	struct is_pod_type<T*>
	{
		static const bool value = true;
	};

	//
	//https://en.cppreference.com/w/cpp/utility/hash
	//
	template<typename _Kty>
	struct hash
	{
		hash() = delete;
	};

	/**
	* 对POD类型包括string要偏特化，并合理设计hash function
	* 字符串hash采用BKDRHash
	* 整数hash采用
	*/
	inline constexpr size_t _FNV_offset_basis = 2166136261U;
	inline constexpr size_t _FNV_prime = 16777619U;

	//
	//https://github.com/microsoft/STL
	//
	inline size_t _Fnv1a_append_bytes(size_t _Val, const unsigned char* const _First,
		const size_t _Count) noexcept { // accumulate range [_First, _First + _Count) into partial FNV-1a hash _Val
		for (size_t _Idx = 0; _Idx < _Count; ++_Idx) {
			_Val ^= static_cast<size_t>(_First[_Idx]);
			_Val *= _FNV_prime;
		}
		return _Val;
	}

	template <class _Kty>
	size_t _Fnv1a_append_value(
		const size_t _Val, const _Kty& _Keyval) noexcept { // accumulate _Keyval into partial FNV-1a hash _Val
		return _Fnv1a_append_bytes(_Val, &reinterpret_cast<const unsigned char&>(_Keyval), sizeof(_Kty));
	}

	template <class _Kty>
	size_t _Hash_representation(const _Kty& _Keyval) noexcept { // bitwise hashes the representation of a key
		return _Fnv1a_append_value(_FNV_offset_basis, _Keyval);
	}

	/**
	* 模板特化对类型严格匹配
	* 精确到每一个const和unsigned等修饰符
	*/
	template<>
	struct hash<const char*> 
	{
		size_t operator()(const char* str)const noexcept{
		
		static unsigned int seed = 131313;//也可以乘以31、131、1313、13131、131313..
		static unsigned int hash = 0;
		while(*str)
		{
			hash = hash*seed + (*str++);
        }
		return hash % 32767;//最好对一个大的素数取余
		}
	};

	template<>
	struct hash<char*>
	{
		size_t operator()(const char* str)const noexcept {

			static unsigned int seed = 131313;//也可以乘以31、131、1313、13131、131313..
			static unsigned int hash = 0;
			while (*str)
			{
				hash = hash * seed + (*str++);
			}
			return hash % 32767;//最好对一个大的素数取余
		}
	};

	template<>
	struct hash<int>
	{
		size_t operator()(int _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<unsigned int>
	{
		size_t operator()(unsigned int _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<long>
	{
		size_t operator()(long _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<unsigned long>
	{
		size_t operator()(unsigned long _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<char>
	{
		size_t operator()(char _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<unsigned char>
	{
		size_t operator()(unsigned char _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<signed char>
	{
		size_t operator()(signed char _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<short>
	{
		size_t operator()(short _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};

	template<>
	struct hash<unsigned short>
	{
		size_t operator()(unsigned short _Keyval)const noexcept {
			return _Hash_representation(_Keyval == 0 ? 0 : _Keyval); // map -0 to 0
		}
	};



}