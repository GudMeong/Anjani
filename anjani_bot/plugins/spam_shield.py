"""Chat SpamShield"""
# Copyright (C) 2020 - 2021  UserbotIndo Team, <https://github.com/userbotindo.git>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import ClassVar, Dict, Union

import joblib
import spamwatch
from motor.motor_asyncio import AsyncIOMotorCollection
from pyrogram import StopPropagation, filters
from pyrogram.errors import ChannelPrivate, UserNotParticipant
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup, User
from requests import exceptions
from spamwatch.types import Ban

from anjani_bot import listener, plugin
from anjani_bot.core import pool
from anjani_bot.utils import ParsedChatMember, user_ban_protected

LOGGER = logging.getLogger(__name__)


class SpamShield(plugin.Plugin):
    name: ClassVar[str] = "SpamShield"

    gban_setting: AsyncIOMotorCollection
    lock: asyncio.locks.Lock
    spmwtch: str

    async def __on_load__(self) -> None:
        self.gban_setting = self.bot.get_collection("GBAN_SETTINGS")
        self.fed_db = self.bot.get_collection("FEDERATIONS")
        self.lock = asyncio.Lock()
        self.spmwtc = self.bot.get_config.spamwatch_api

        gh_token = self.bot.get_config.gh_token
        self.run_predict = False
        if gh_token:
            self.spam_db = self.bot.get_collection("SPAM_DUMP")
            predict_url = self.bot.get_config.predict_url
            if predict_url:
                self.log.info("Downloading spam prediction model")
                async with self.bot.http.get(
                    predict_url,
                    headers={
                        "Authorization": f"token {gh_token}",
                        "Accept": "application/vnd.github.v3.raw",
                    },
                ) as res:
                    if res.status == 200:
                        with open("predict_model.pkl", "wb") as file:
                            file.write(await res.read())
                        self.model = joblib.load("predict_model.pkl")
                        self.run_predict = True
                        self.log.info("Model loaded")
                        return
            self.log.warning("Failed to donwload spam prediction model!")

    async def __migrate__(self, old_chat, new_chat):
        async with self.lock:
            await self.gban_setting.update_one(
                {"chat_id": old_chat}, {"$set": {"chat_id": new_chat}}
            )

    async def __backup__(self, chat_id, data=None) -> Union[Dict, None]:
        if data and data.get(self.name):
            async with self.lock:
                await self.gban_setting.update_one(
                    {"chat_id": chat_id},
                    {"$set": data[self.name]},
                    upsert=True,
                )
        elif not data:
            return await self.gban_setting.find_one({"chat_id": chat_id}, {"_id": False})

    def _build_hash(self, content):
        return hashlib.sha256(content.strip().encode()).hexdigest()

    @pool.run_in_thread
    def _predict(self, text: str):
        return self.model.predict_proba([text])

    @pool.run_in_thread
    def sw_check(self, user_id: int) -> Union[Ban, None]:
        """Check on SpawmWatch"""
        if not self.spmwtc:
            LOGGER.warning("No SpamWatch API!")
            return None
        try:
            return spamwatch.Client(self.spmwtc).get_ban(user_id)
        except exceptions.ConnectionError:
            return None

    async def cas_check(self, user_id: int) -> Union[str, bool]:
        """Check on CAS"""
        async with self.bot.http.get(f"https://api.cas.chat/check?user_id={user_id}") as res:
            data = json.loads(await res.text())
        if data["ok"]:
            return "https://cas.chat/query?u={}".format(user_id)
        return False

    async def cas_fban(self, user: User) -> None:
        """fban CAS-banned user on client official feds"""
        await self.fed_db.update_one(
            {"_id": "AnjaniSpamShield"},
            {
                "$set": {
                    f"banned.{int(user.id)}": {
                        "name": ParsedChatMember(user).fullname,
                        "reason": "Automated-fban due to CAS-Banned",
                        "time": time.time(),
                    }
                }
            },
            upsert=False,
        )

    async def chat_gban(self, chat_id) -> bool:
        """Return Spam_Shield setting"""
        setting = await self.gban_setting.find_one({"chat_id": chat_id})
        return setting["setting"] if setting else True

    @listener.on(filters=filters.regex(r"spam_check_(t|f)\[(.*?)\]"), update="callbackquery")
    async def spam_vote(self, query):
        message = query.message
        content_hash = re.compile(r"([A-Fa-f0-9]{64})").search(message.text)
        author = str(query.from_user.id)
        users_on_correct = users_on_incorrect = []
        total_correct = total_incorrect = 0

        if not content_hash:
            self.log.warning("Can't get hash from 'MessageID: %d'", message.message_id)
            return

        correct = re.compile(r"spam_check_t(.*?)").match(query.data)
        if message.reply_markup and isinstance(message.reply_markup, InlineKeyboardMarkup):
            data = message.reply_markup.inline_keyboard[0][0].callback_data
            if isinstance(data, bytes):
                data = data.decode()

            users_on_correct = re.findall("[0-9]+", data)

        incorrect = re.compile(r"spam_check_f(.*?)").match(query.data)
        if message.reply_markup and isinstance(message.reply_markup, InlineKeyboardMarkup):
            data = message.reply_markup.inline_keyboard[0][1].callback_data
            if isinstance(data, bytes):
                data = data.decode()

            users_on_incorrect = re.findall("[0-9]+", data)

        if correct:
            if author in users_on_incorrect:  # Check user in incorrect data
                users_on_incorrect.remove(author)
            if author in users_on_correct:
                users_on_correct.remove(author)
            else:
                users_on_correct.append(author)
        elif incorrect:
            if author in users_on_correct:  # Check user in correct data
                users_on_correct.remove(author)
            if author in users_on_incorrect:
                users_on_incorrect.remove(author)
            else:
                users_on_incorrect.append(author)

        total_correct, total_incorrect = len(users_on_correct), len(users_on_incorrect)
        users_on_correct = f"[{', '.join(users_on_correct)}]"
        users_on_incorrect = f"[{', '.join(users_on_incorrect)}]"
        button = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        text=f"✅ Correct ({total_correct})",
                        callback_data=f"spam_check_t{users_on_correct}",
                    ),
                    InlineKeyboardButton(
                        text=f"❌ Incorrect ({total_incorrect})",
                        callback_data=f"spam_check_f{users_on_incorrect}",
                    ),
                ]
            ]
        )
        await asyncio.gather(
            self.spam_db.update_one(
                {"_id": content_hash[0]},
                {"$set": {"spam": total_correct, "ham": total_incorrect}},
            ),
            query.edit_message_reply_markup(reply_markup=button),
        )

    async def predict(self, message):
        text = message.text or message.caption
        text = repr(text.strip())
        res = await self._predict(text)

        prob = res[0][1]
        if prob >= 0.6:
            text_hash = self._build_hash(text)
            data = await self.spam_db.find_one({"_id": text_hash})
            if data:  # Don't send any duplicates
                return
            prob = str(prob * 10 ** 2)[0:7]  # Convert to str to prevent rounding
            text = (
                "#SPAM_PREDICTION\n\n"
                f"**Prediction Result:** `{prob}`\n"
                f"**Message Hash:** `{text_hash}`\n"
                f"\n**====== CONTENT =======**\n\n{message.text}"
            )
            await asyncio.gather(
                self.spam_db.update_one(
                    {"_id": text_hash},
                    {
                        "$set": {
                            "text": message.text.strip(),
                            "spam": 0,
                            "ham": 0,
                            "chat": message.chat.id,
                            "id": message.from_user.id,
                        }
                    },
                    upsert=True,
                ),
                self.bot.client.send_message(
                    chat_id=-1001314588569,
                    text=text,
                    disable_web_page_preview=True,
                    reply_markup=InlineKeyboardMarkup(
                        [
                            [
                                InlineKeyboardButton(
                                    text="✅ Correct (0)",
                                    callback_data=f"spam_check_t[]",
                                ),
                                InlineKeyboardButton(
                                    text="❌ Incorrect (0)",
                                    callback_data=f"spam_check_f[]",
                                ),
                            ]
                        ]
                    ),
                ),
            )

    async def shield_pref(self, chat_id, setting: bool):
        """Turn on/off SpamShield in chats"""
        async with self.lock:
            await self.gban_setting.update_one(
                {"chat_id": chat_id}, {"$set": {"setting": setting}}, upsert=True
            )

    @listener.on(filters=filters.all & filters.group, group=1, update="message")
    async def shield(self, message):
        """Check handler"""
        if message.chat is None:  # sanity check
            return

        try:
            if (
                await self.chat_gban(message.chat.id)
                and (
                    await self.bot.client.get_chat_member(message.chat.id, "me")
                ).can_restrict_members
            ):
                user = message.from_user
                chat = message.chat
                if user and not await user_ban_protected(self.bot, chat.id, user.id):
                    await self.check_and_ban(user, chat.id)
                elif message.new_chat_members:
                    for member in message.new_chat_members:
                        await self.check_and_ban(member, chat.id)
        except (ChannelPrivate, UserNotParticipant):
            pass

        if (
            self.run_predict
            and message.from_user.id not in self.bot.staff_id
            and (message.text or message.caption)
        ):
            self.bot.loop.create_task(self.predict(message))

    async def check_and_ban(self, user, chat_id):
        """Shield Check users."""
        user_id = user.id
        _cas = await self.cas_check(user_id)
        _sw = await self.sw_check(user_id)
        if _cas or _sw:
            userlink = f"[{user.first_name}](tg://user?id={user_id})"
            reason = f"[link]({_cas})" if _cas else _sw.reason
            if _cas:
                banner = "[Combot Anti Spam](t.me/combot)"
                await self.cas_fban(user)
            else:
                banner = "[Spam Watch](t.me/SpamWatch)"
            text = await self.bot.text(chat_id, "banned-text", userlink, user_id, reason, banner)
            await asyncio.gather(
                self.bot.client.kick_chat_member(chat_id, user_id),
                self.bot.client.send_message(
                    chat_id,
                    text=text,
                    parse_mode="markdown",
                    disable_web_page_preview=True,
                ),
                self.bot.channel_log(
                    "#SPAM_SHIELD LOG\n"
                    f"**User**: {userlink} banned on {chat_id}\n"
                    f"**ID**: {user_id}\n"
                    f"**Reason**: {reason}"
                ),
            )
            raise StopPropagation

    @listener.on("spamshield", admin_only=True)
    async def shield_setting(self, message):
        """Set spamshield setting"""
        chat_id = message.chat.id
        if len(message.command) >= 1:
            arg = message.command[0]
            if arg.lower() in ["on", "true", "enable"]:
                await self.shield_pref(chat_id, True)
                await message.reply_text(await self.bot.text(chat_id, "spamshield-set", "on"))
            elif arg.lower() in ["off", "false", "disable"]:
                await self.shield_pref(chat_id, False)
                await message.reply_text(await self.bot.text(chat_id, "spamshield-set", "off"))
            else:
                await message.reply_text(await self.bot.text(chat_id, "err-invalid-option"))
        else:
            setting = await self.chat_gban(message.chat.id)
            await message.reply_text(await self.bot.text(chat_id, "spamshield-view", setting))

    @listener.on("spam", staff_only=True)
    async def spam_log(self, message):
        """Manual spam detection by bot staff"""
        if message.chat.type != "private":
            return await message.reply_text("This command only avaliable on PM's!")

        user_id = None
        if message.reply_to_message:
            content = message.reply_to_message.text or message.reply_to_message.caption
            if message.reply_to_message.forward_from:
                user_id = message.reply_to_message.forward_from.id
        else:
            text = message.text.split(" ", 1)
            if len(text) < 2:
                return await message.reply_text(
                    "Give me a text or reply to a message / forwarded message"
                )
            content = text[1].strip()

        content_hash = self._build_hash(content)

        text = (
            "#SPAM\n\n"
            f"**Message Hash:** `{content_hash}`\n"
            f"\n**====== CONTENT =======**\n\n{content}"
        )

        await asyncio.gather(
            self.spam_db.update_one(
                {"_id": content_hash},
                {
                    "$set": {
                        "text": content.strip(),
                        "spam": 1,
                        "ham": 0,
                        "chat": None,
                        "id": user_id,
                    }
                },
                upsert=True,
            ),
            self.bot.client.send_message(
                chat_id=-1001314588569,
                text=text,
                disable_web_page_preview=True,
            ),
        )
