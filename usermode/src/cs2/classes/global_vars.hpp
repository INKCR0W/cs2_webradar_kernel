#pragma once

namespace usermode::classes
{
	class c_global_vars
	{
	public:
		std::string get_map_name()
		{
			// @https://www.unknowncheats.me/forum/3870682-post1183.html
			const auto current_map_name = m_driver.read_t<std::uint64_t>(this + 0x188);
			if (!current_map_name)
				return "invalid";

			const auto map_name = m_driver.read_string(current_map_name, 64);
			if (map_name.empty())
				return "invalid";

			return map_name;
		}
	};
}