#include "pch.hpp"

src::cs2::c_base_player* src::cs2::c_base_player::get()
{
	return m_memory.read_t<c_base_player*>(m_base_player);
}