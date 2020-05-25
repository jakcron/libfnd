#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <fnd/SimpleTextOutput.h>

void fnd::SimpleTextOutput::hxdStyleDump(const byte_t* data, size_t len, size_t row_len, size_t byte_grouping_size)
{
	// iterate over blocks
	for (size_t i = 0; i < (len / row_len); i++)
	{
		printf("%08" PRIx64 " | ", (uint64_t)(i * row_len));
		// for block i print each byte
		for (size_t j = 0; j < row_len; j++)
		{
			printf("%02X", data[(i * row_len) + j]);
			if (((j+1) % byte_grouping_size) == 0) 
			{
				putchar(' ');
			}
		}
		printf(" ");
		for (size_t j = 0; j < row_len; j++)
		{
			printf("%c", iscntrl(data[(i * row_len) + j]) ? '.' : data[(i * row_len) + j]);
		}
		printf("\n");
	}
	if ((len % row_len) > 0)
	{
		size_t i = (len / row_len);
		printf("%08" PRIx64 " | ", (uint64_t)(i * row_len));
		// for block i print each byte
		for (size_t j = 0; j < row_len; j++)
		{
			if (j < (len % row_len))
				printf("%02X", data[(i * row_len) + j]);
			else
				printf("  ");
			if (((j+1) % byte_grouping_size) == 0) 
			{
				putchar(' ');
			}
		}
		printf(" ");
		for (size_t j = 0; j < row_len; j++)
		{
			if (j < (len % row_len))
				printf("%c", iscntrl(data[(i * row_len) + j]) ? '.' : data[(i * row_len) + j]);
			else
				printf(" ");
		}
		printf("\n");
	}
}

void fnd::SimpleTextOutput::hxdStyleDump(const byte_t* data, size_t len)
{
	hxdStyleDump(data, len, kDefaultRowLen, kDefaultByteGroupingSize);
}

void fnd::SimpleTextOutput::hexDump(const byte_t* data, size_t len, size_t row_len, size_t indent_len)
{
	for (size_t i = 0; i < len; i += row_len)
	{
		for (size_t j = 0; j < indent_len; j++)
			std::cout << " ";
		std::cout << arrayToString(data+i, _MIN(len-i, row_len), true, "") << std::endl;
	}
}

void fnd::SimpleTextOutput::hexDump(const byte_t* data, size_t len)
{
	std::cout << arrayToString(data, len, true, "") << std::endl;
}

std::string fnd::SimpleTextOutput::arrayToString(const byte_t* data, size_t len, bool upper_case, const std::string& separator)
{
	std::stringstream ss;

	if (upper_case)
			ss << std::uppercase;
	for (size_t i = 0; i < len; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (uint32_t)data[i];
		if (i+1 < len)
			ss << separator;
	}
	return ss.str();
}

inline byte_t charToByte(char chr)
{
	if (chr >= 'a' && chr <= 'f')
		return (chr - 'a') + 0xa;
	else if (chr >= 'A' && chr <= 'F')
		return (chr - 'A') + 0xa; 
	else if (chr >= '0' && chr <= '9')
		return chr - '0';
	return 0;
}

void fnd::SimpleTextOutput::stringToArray(const std::string& str, fnd::Vec<byte_t>& array)
{
	size_t size = str.size();
	if ((size % 2))
	{
		return;
	}

	array.alloc(size/2);

	for (size_t i = 0; i < array.size(); i++)
	{
		array[i] = (charToByte(str[i * 2]) << 4) | charToByte(str[(i * 2) + 1]);
	}
}

void fnd::SimpleTextOutput::dumpStringList(const std::vector<std::string>& str_list, size_t row_len, size_t indent_len)
{
	// create indentation string
	std::string indent_str = "";
	for (size_t i = 0; i < indent_len; i++)
	{
		indent_str += " ";
	}

	// create delimiter string
	std::string delimiter_str = ", ";

	size_t printed_len = 0;
	for (auto itr = str_list.begin(); itr != str_list.end(); itr++)
	{
		// format the strings
		// wrap the line after row_len multples
		if (printed_len > row_len || printed_len == 0)
		{
			// don't print the new line if this is the first string
			if (itr != str_list.begin())
				std::cout << delimiter_str << std::endl;

			// print indent
			std::cout << indent_str;

			// reset printed_len
			printed_len = 0;
		}
		// within a line we want to separate the next string from the last one with a comma and a space
		else
		{
			std::cout << delimiter_str;
		}
		
		// print string
		std::cout << *itr;

		// note the length of the string printed
		printed_len += itr->size() + delimiter_str.size();
	}
	std::cout << std::endl;
}