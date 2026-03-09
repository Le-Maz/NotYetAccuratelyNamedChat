package me.lmazur.notyetaccuratelynamedchat

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform