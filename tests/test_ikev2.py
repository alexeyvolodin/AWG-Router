"""Проверки IKEv2: параметры выхода, маршрутизация, здоровье и сохранение настроек."""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("PANEL_PASSWORD", "test-password")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # test_api, test_v115
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import awgconf, checks, config, ikev2, nftgen  # noqa: E402
from app.api import backup  # noqa: E402
from app.api import state as api_state  # noqa: E402
from app.engine import Engine, UpRT  # noqa: E402
from app.panel import engine as panel_engine, store as panel_store  # noqa: E402


def vpn_config(**changes):
    """Тестовые реквизиты не требуют доступа к корпоративному серверу."""
    fields = {"kind": "ikev2", "host": "vpn.example.com", "remote_id": "vpn.example.com",
              "local_id": "", "user": "employee", "password": "s e c r e t", "ca": "", "mtu": 1280}
    fields.update(changes)
    return json.dumps(fields)


def policy_chain(ruleset: str, name: str = "p_global") -> str:
    """Тело одной цепочки nftables: порядок строк внутри неё и есть порядок решений."""
    return ruleset.split(f"\tchain {name} {{", 1)[1].split("\n\t}", 1)[0]


class Ikev2ConfigTest(unittest.TestCase):
    """Разбор сохраняет секреты точно и отклоняет опасные или неполные параметры."""

    def test_roundtrip(self):
        """Вход JSON превращается в IKEv2 и повторно разбирается без потери пароля."""
        pc = awgconf.parse_upstream(vpn_config(host="VPN.example.com", password='p\\a"ss #{}'))
        self.assertEqual(pc.kind, "ikev2")
        self.assertEqual(pc.endpoint, "vpn.example.com:500")
        self.assertEqual(pc.ikev2["password"], 'p\\a"ss #{}')
        self.assertEqual(awgconf.parse_upstream(pc.raw), pc)
        self.assertEqual(pc.address, "")

    def test_deeply_nested_json_is_not_a_config(self):
        """JSON с огромной вложенностью даёт ошибку конфига (HTTP 400), а не сбой разбора (HTTP 500)."""
        depth = 100_000
        with self.assertRaises(awgconf.ConfigError) as cm:
            awgconf.parse_upstream("{" + '"a":{' * depth + '"b":1' + "}" * depth + "}")
        self.assertEqual(cm.exception.msg.key, "cfg.unrecognized")

    def test_remote_id_defaults_to_host(self):
        """Пустой удалённый ID означает проверку сертификата по имени сервера."""
        pc = awgconf.parse_upstream(vpn_config(remote_id=""))
        self.assertEqual(pc.ikev2["remote_id"], "vpn.example.com")

    def test_invalid_settings(self):
        """Пустые реквизиты, неверный CA и управляющие символы запрещены до запуска VPN."""
        for changes in ({"host": ""}, {"host": "host; command"}, {"user": ""}, {"password": ""},
                        {"remote_id": "%any"}, {"local_id": "bad\nID"}, {"password": "bad\x00pw"},
                        {"ca": "not a certificate"}, {"ca": "не сертификат"}, {"remote_id": "*.example.com"},
                        {"mtu": 900}, {"mtu": "bad"}, {"mtu": 1280.5}, {"mtu": float("inf")}):
            with self.subTest(changes=changes), self.assertRaises(awgconf.ConfigError):
                awgconf.parse_upstream(vpn_config(**changes))


class Ikev2RuntimeTest(unittest.TestCase):
    """Конфиги strongSwan изолируют выходы и сохраняют проверку личности сервера."""

    def test_generated_configuration(self):
        """Пароль со спецсимволами экранируется, а интерфейс получает собственный ID."""
        fields = ikev2.normalize(json.loads(vpn_config(password='p\\\\a"ss')))
        conf = ikev2.connection_config(fields, "awgr7", "198.51.100.7", "/run/test/ca.pem")
        self.assertIn('auth = eap-mschapv2', conf)
        self.assertIn('auth = pubkey', conf)
        self.assertIn('id = "vpn.example.com"', conf)
        self.assertIn('if_id_in = 1096220679', conf)
        self.assertIn('if_id_out = 1096220679', conf)
        self.assertIn('vips = 0.0.0.0', conf)
        self.assertIn(f'set_mark_out = {ikev2.OUTER_MARK:#x}/0xffffffff', conf)
        import base64
        self.assertIn('secret = 0s' + base64.b64encode(fields["password"].encode()).decode(), conf)
        self.assertNotIn("%any", conf)

    def test_password_encoding_prefixes_are_literal(self):
        """Префиксы 0x и 0s в пароле не должны интерпретироваться как формат его хранения."""
        import base64
        import re
        for password in ("0x4142", "0X4142", "0sYWJj", "0SYWJj"):
            with self.subTest(password=password):
                fields = ikev2.normalize(json.loads(vpn_config(password=password)))
                conf = ikev2.connection_config(fields, "awgr7", "198.51.100.7")
                encoded = re.search(r"secret = 0s([A-Za-z0-9+/=]+)", conf)
                self.assertIsNotNone(encoded)
                self.assertEqual(base64.b64decode(encoded.group(1)).decode(), password)

    def test_daemon_configuration(self):
        """Демон использует случайные порты, собственный сокет и не меняет адреса и DNS цели."""
        conf = ikev2.daemon_config("/tmp/ike7/vici.sock")
        for setting in ("port = 0", "port_nat_t = 0", "install_routes = no", "install_virtual_ip = no",
                        "unix:///tmp/ike7/vici.sock", f"fwmark = {ikev2.OUTER_MARK:#x}"):
            self.assertIn(setting, conf)
        self.assertNotIn("resolve", conf)

    def test_outer_mark_is_separate_from_panel_marks(self):
        """Метка внешних пакетов IKE/ESP не совпадает ни с одной меткой панели.

        Вход: OUTER_MARK и метки панели из config/nftgen.
        Ожидание: нет общих битов с QUIC_CT_BIT (ct mark решений QUIC); по маске EXIT_MASK она не похожа
        на метку выхода или политики sniproxy.py, иначе страховки c_forward/c_guard_post отбросили бы ESP.
        """
        self.assertEqual(ikev2.OUTER_MARK & config.QUIC_CT_BIT, 0)
        self.assertNotIn(ikev2.OUTER_MARK & nftgen.EXIT_MASK, (config.MARK_BASE, config.SNIFF_OUT_BASE))
        self.assertNotIn(ikev2.OUTER_MARK, (config.MARK_BLOCK, config.SNIFF_MARK, config.QUIC_PASS_MARK,
                                            config.QUIC_DIRECT_MARK))

    def test_stale_runtime_does_not_write_through_old_ca_symlink(self):
        """После перезапуска старый каталог заменяется до записи нового сертификата."""
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            outside = Path(root) / "system-ca"
            outside.mkdir()
            work = Path(root) / "ike"
            work.mkdir()
            (work / "x509ca").symlink_to(outside, target_is_directory=True)
            runtime = ikev2.Runtime(str(work), "awgr7", root + "/awgr7.log")
            fields = json.loads(vpn_config(ca="new company certificate"))
            runtime._prepare(fields, "198.51.100.7")
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((work / "x509ca").is_symlink())
            self.assertEqual((work / "x509ca/company.pem").read_text(), "new company certificate")
            self.assertEqual((work / "swanctl.conf").stat().st_mode & 0o777, 0o600)

    def test_intermediates_complete_chain_without_becoming_trusted(self):
        """Кросс-подписи достраивают цепочку сервера, но доверие остаётся только у корней из x509ca.

        Вход: каталог с одним промежуточным сертификатом, выход с CA компании и без него.
        Ожидание: файл доступен в x509, в x509ca его нет; закрытие выхода не удаляет общий каталог.
        """
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            bundle = Path(root) / "bundle"
            bundle.mkdir()
            (bundle / "cross.pem").write_text("cross-signed root")
            for ca in ("", "company certificate"):
                with self.subTest(company_ca=bool(ca)):
                    work = Path(root) / "ike"
                    runtime = ikev2.Runtime(str(work), "awgr7", root + "/awgr7.log", intermediates=str(bundle))
                    runtime._prepare(json.loads(vpn_config(ca=ca)), "198.51.100.7")
                    self.assertEqual((work / "x509/cross.pem").read_text(), "cross-signed root")
                    self.assertNotIn("cross.pem", os.listdir(work / "x509ca"))
                    runtime.close()
                    self.assertEqual((bundle / "cross.pem").read_text(), "cross-signed root")

    def test_server_verification_failure_from_log(self):
        """Отказ в доверии серверу распознаётся по журналу charon, иначе причина не угадывается.

        Вход: журнала нет; строки отказа для RSA- и ECDSA-ключа; обычный ход подключения.
        Ожидание: ike.untrusted_server только для строк отказа.
        """
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "awgr7.log"
            runtime = ikev2.Runtime(root + "/ike", "awgr7", str(log))
            self.assertIsNone(runtime.failure())
            for key in ("RSA", "ECDSA"):
                with self.subTest(key=key):
                    log.write_text("02[IKE] received end entity cert \"CN=vpn.example.com\"\n"
                                   f"02[IKE] no trusted {key} public key found for 'vpn.example.com'\n")
                    self.assertEqual(runtime.failure().key, "ike.untrusted_server")
            log.write_text("10[IKE] initiating IKE_SA awgr7[1] to 198.51.100.7\n13[IKE] establishing CHILD_SA net{1}\n")
            self.assertIsNone(runtime.failure())

    def test_unknown_runtime_owner_preserves_existing_files(self):
        """Ошибка чтения владельца не разрешает удалять его сертификаты или IPsec-состояние."""
        from pathlib import Path
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as root:
            work = Path(root) / "ike"
            work.mkdir()
            existing = work / "company.pem"
            existing.write_text("existing certificate")
            runtime = ikev2.Runtime(str(work), "awgr7", root + "/log")
            with mock.patch("app.ikev2.open", side_effect=PermissionError, create=True), \
                    mock.patch("app.ikev2.subprocess.run") as command:
                with self.assertRaises(ikev2.Ikev2Error):
                    runtime.start(SimpleNamespace(pid=42), json.loads(vpn_config()), "198.51.100.7")
                runtime.close()
            self.assertEqual(existing.read_text(), "existing certificate")
            command.assert_not_called()

    def test_cleanup_after_crash_only_removes_owned_ipsec(self):
        """После аварии демона удаляются только политики и SA его зарезервированного ID."""
        import subprocess
        with tempfile.TemporaryDirectory() as root:
            runtime = ikev2.Runtime(root + "/ike", "awgr7", root + "/awgr7.log")
            runtime._prepare(json.loads(vpn_config()), "198.51.100.7")
            runtime.target_pid = 42
            runtime.proc = mock.Mock()
            runtime.proc.poll.return_value = 1
            policies = ("src 10.9.0.7/32 dst 0.0.0.0/0\n dir out priority 1\n"
                        " tmpl src 192.0.2.1 dst 192.0.2.2 proto esp reqid 1096220679 mode tunnel\n if_id 0x41570007\n"
                        "src 10.9.0.8/32 dst 0.0.0.0/0\n dir out priority 1\n"
                        " tmpl src 192.0.2.1 dst 192.0.2.2 proto esp reqid 1096220680 mode tunnel\n if_id 0x41570008\n")
            with mock.patch.object(ikev2.subprocess, "run",
                                   return_value=subprocess.CompletedProcess([], 0, policies, "")) as execute:
                runtime.close()
            commands = [call.args[0] for call in execute.call_args_list]
            self.assertTrue(any(command[-2:] == ["reqid", "1096220679"] for command in commands))
            deletes = [command for command in commands if "policy" in command and "delete" in command]
            self.assertEqual(len(deletes), 1)
            self.assertIn("10.9.0.7/32", deletes[0])
            self.assertNotIn("10.9.0.8/32", deletes[0])

    def test_status_requires_installed_child_and_virtual_ipv4(self):
        """Одна IKE-сессия без рабочего IPsec-туннеля не считается готовым выходом."""
        output = ("list-sa event {awgr7 {state=ESTABLISHED local-vips=[10.9.0.7] child-sas {net-1 {name=net "
                  "state=INSTALLED if-id-in=41570007 if-id-out=41570007 bytes-in=123 bytes-out=456 "
                  "local-ts=[10.9.0.7/32] remote-ts=[0.0.0.0/0]}}}}")
        self.assertEqual(ikev2.parse_status(output, 1096220679),
                         {"healthy": True, "address": "10.9.0.7", "rx": 123, "tx": 456})
        for text in ("", output.replace("INSTALLED", "INSTALLING"), output.replace("10.9.0.7", "fd00::7"),
                     output.replace("41570007", "41570008"),
                     output.replace("local-ts=[10.9.0.7/32]", "local-ts=[10.9.0.8/32]")):
            with self.subTest(text=text):
                self.assertFalse(ikev2.parse_status(text, 1096220679)["healthy"])


class Ikev2RoutingTest(unittest.TestCase):
    """Правила, nftables, здоровье и резервные копии принимают выход IKEv2."""

    def setUp(self):
        """Изолированное состояние оставляет глобальное хранилище панели неизменным."""
        from test_api import good_state
        self.st = good_state()
        self.st["upstreams"][0]["config"] = vpn_config()
        self.st["lists"].append({"id": "l_sites", "kind": "domains", "source": "portal.example.com", "name": "Sites"})
        self.st["lists"].append({"id": "l_company", "kind": "manual", "source": "10.55.0.0/16", "name": "Company"})

    def _running_engine(self) -> Engine:
        """Движок с запущенным и рабочим выходом IKEv2 номер 1 (u000001)."""
        engine = Engine(panel_store)
        engine.rt["u000001"] = UpRT(1, "hash", "target")
        engine.health["u000001"] = {"healthy": True}
        return engine

    def _ruleset(self, engine: Engine, rules: list[dict], **kw) -> str:
        """Набор правил nftables для общей политики rules с выходом по умолчанию «напрямую».
        kw — sniff_port, quic, hold для build_ruleset."""
        self.st["routing"]["default"] = "direct"
        self.st["routing"]["rules"] = rules
        target = mock.Mock(iface="awg0")
        with mock.patch.object(engine, "_cidrs", return_value=["10.55.0.0/16"]):
            return engine.build_ruleset(target, self.st, **kw)

    def test_domain_rule_and_backup(self):
        """Домен назначается IKEv2, а резервная копия сохраняет правило и реквизиты."""
        rules = [{"lists": ["l_sites"], "outbound": "up:u000001", "enabled": True}]
        self.st["routing"]["rules"] = checks.rules(self.st, rules)
        restored = backup.clean_backup_state(self.st)
        self.assertEqual(restored["routing"]["rules"][0]["outbound"], "up:u000001")
        self.assertEqual(awgconf.parse_upstream(restored["upstreams"][0]["config"]).kind, "ikev2")

    def test_health_and_dynamic_snat(self):
        """SNAT использует выданный VPN адрес, а после потери SA выход перестаёт быть рабочим."""
        engine = Engine(panel_store)
        runtime = UpRT(1, "hash", "target")
        runtime.ike = mock.Mock()
        runtime.ike.status.return_value = {"healthy": True, "address": "10.9.0.17", "rx": 42, "tx": 24}
        engine.rt["u000001"] = runtime
        target = mock.Mock()
        engine._update_health(target, self.st)
        self.assertTrue(engine.health["u000001"]["healthy"])
        self.assertEqual(engine.health["u000001"]["kind"], "ikev2")
        self.assertEqual(engine._up_list(self.st)[0]["snat"], "10.9.0.17")
        runtime.ike.status.return_value = {"healthy": False, "address": "", "rx": 0, "tx": 0}
        engine._update_health(target, self.st)
        self.assertFalse(engine.health["u000001"]["healthy"])
        self.assertEqual(engine._up_list(self.st)[0]["snat"], "")
        target.ns.assert_not_called()

    def test_exit_card_shows_assigned_address(self):
        """Карточка выхода показывает адрес, выданный сервером IKEv2, а не пустой адрес из конфига."""
        u = self.st["upstreams"][0]
        with mock.patch.dict(panel_engine.health, {u["id"]: {"healthy": True, "address": "10.9.0.17"}}):
            view = api_state._upstream_view(self.st, u)
        self.assertEqual(view["kind"], "ikev2")
        self.assertEqual(view["address"], "10.9.0.17")

    def test_server_verification_failure_is_shown(self):
        """Причина из журнала видна и пока выход ждёт сессию, и после остановки попыток.

        Вход: SA не установлена, журнал сообщает об отказе в доверии; затем прошло 120 с.
        Ожидание: ошибка ike.untrusted_server в здоровье выхода в обоих состояниях.
        """
        from app.i18n import Msg
        engine = Engine(panel_store)
        runtime = UpRT(1, "hash", "target")
        runtime.ike = mock.Mock()
        runtime.ike.status.return_value = {"healthy": False, "address": "", "rx": 0, "tx": 0}
        runtime.ike.failure.return_value = Msg("ike.untrusted_server")
        engine.rt["u000001"] = runtime
        engine._update_health(mock.Mock(), self.st)
        self.assertEqual(engine.health["u000001"]["error"].key, "ike.untrusted_server")
        runtime.ike_down_since -= 120
        with mock.patch.object(engine, "_stop_up"):
            engine._update_health(mock.Mock(), self.st)
        self.assertEqual(engine.health["u000001"]["state"], "error")
        self.assertEqual(engine.health["u000001"]["error"].key, "ike.untrusted_server")

    def test_connecting_exit_wakes_pass_once_child_sa_is_installed(self):
        """Клиенты только что запущенного выхода в блоке; проход будится, как только CHILD_SA установлена.

        Вход: выход IKEv2 в состоянии «подключается»; затем charon сообщает установленную SA.
        Ожидание: _connecting_due ложно до SA и истинно после; `awg show` на XFRM-интерфейсе не вызывается.
        """
        engine = Engine(panel_store)
        runtime = UpRT(1, "hash", "target")
        runtime.ike = mock.Mock()
        runtime.ike.status.return_value = {"healthy": False, "address": "", "rx": 0, "tx": 0}
        runtime.ike.failure.return_value = None
        engine.rt["u000001"] = runtime
        engine._update_health(mock.Mock(), self.st)
        self.assertEqual(engine.health["u000001"]["state"], "connecting")
        target = mock.Mock()
        self.assertFalse(engine._connecting_due(target, time.time()))
        runtime.ike.status.return_value = {"healthy": True, "address": "10.9.0.17", "rx": 0, "tx": 0}
        self.assertTrue(engine._connecting_due(target, time.time()))
        target.ns.assert_not_called()

    def test_pass_with_only_ikev2_exits_skips_awg_dump(self):
        """Проход без выходов AWG не запускает `awg show all dump`: XFRM-интерфейсы IKEv2 в нём не видны."""
        engine = Engine(panel_store)
        engine.rt["u000001"] = UpRT(1, "hash", "target")
        target = mock.Mock()
        with mock.patch.object(config, "DRY_RUN", False):
            engine._pass_dumps(target, self.st)
        self.assertNotIn(["awg", "show", "all", "dump"], [call.args[0] for call in target.ns.call_args_list])

    def test_private_corporate_website_is_intercepted(self):
        """Частный адрес корпоративного сайта не обходит доменное правило IKEv2."""
        rules = self._ruleset(self._running_engine(),
                              [{"lists": ["l_sites"], "outbound": "up:u000001", "enabled": True}], sniff_port=10443)
        policy = policy_chain(rules)
        self.assertLess(policy.index("tcp dport { 80, 443 }"), policy.index("ip daddr @local4"))

    def test_private_corporate_website_keeps_named_quic(self):
        """QUIC, разобранный по имени, не блокируется строкой перехвата частных сайтов IKEv2.

        Вход: доменное правило на IKEv2, посредник и очередь QUIC работают.
        Ожидание: строка блока UDP 443 до local4 пропускает метку QUIC_PASS_MARK.
        """
        rules = self._ruleset(self._running_engine(),
                              [{"lists": ["l_sites"], "outbound": "up:u000001", "enabled": True}],
                              sniff_port=10443, quic=True)
        policy = policy_chain(rules)
        line = f"udp dport 443 meta mark != {config.QUIC_PASS_MARK:#x} goto o_block"
        self.assertIn(line, policy)
        self.assertLess(policy.index(line), policy.index("ip daddr @local4"))

    def test_private_network_rule_precedes_local_bypass(self):
        """Явно выбранная сеть компании идёт в IKEv2, прочие частные сети остаются напрямую."""
        rules = self._ruleset(self._running_engine(),
                              [{"lists": ["l_company"], "outbound": "up:u000001", "enabled": True}])
        policy = policy_chain(rules)
        self.assertIn("ip daddr @local4 ip daddr @l_l_company goto o_u1", policy)
        self.assertIn("ip daddr @local4 goto o_direct", policy)

    def test_postrouting_guard_lets_ikev2_packets_into_ipsec(self):
        """Страховка c_guard_post не отбрасывает пакет выхода IKEv2 на пути в IPsec.

        Перед шифрованием XFRM ядро ещё раз проводит внутренний пакет через postrouting: метка у него ещё
        выхода (0x2001), а выходной интерфейс уже внешний (маршрут к серверу IKEv2), не awgr*.
        Вход: работающий выход IKEv2 номер 1 и сетевое правило на него.
        Ожидание: до правила drop стоит пропуск именно его метки при маршруте IPsec; без выходов IKEv2
        (правила «до панели») такого пропуска нет.
        """
        rules = self._ruleset(self._running_engine(),
                              [{"lists": ["l_company"], "outbound": "up:u000001", "enabled": True}])
        guard = policy_chain(rules, "c_guard_post")
        allow = f"meta mark {nftgen.mark_for(1):#x} rt ipsec exists accept"
        self.assertIn(allow, guard)
        self.assertLess(guard.index(allow), guard.index("drop"))
        hold = self._ruleset(self._running_engine(),
                             [{"lists": ["l_company"], "outbound": "up:u000001", "enabled": True}], hold=True)
        self.assertNotIn("rt ipsec", hold)

    def test_strict_block_keeps_local_networks(self):
        """Блок «правила по доменам не работают» не задевает местные сети, как и без IKEv2.

        Вход: галочка routing.strict, посредника нет, доменное правило и сеть компании на IKEv2.
        Ожидание: сеть компании идёт в IKEv2, прочие частные сети напрямую, всё остальное в блок.
        """
        self.st["routing"]["strict"] = True
        rules = self._ruleset(self._running_engine(),
                              [{"lists": ["l_sites"], "outbound": "up:u000001", "enabled": True},
                               {"lists": ["l_company"], "outbound": "up:u000001", "enabled": True}])
        lines = [x.strip() for x in policy_chain(rules).splitlines() if x.strip()]
        self.assertEqual(lines, ["ip daddr @local4 ip daddr @l_l_company goto o_u1",
                                 "ip daddr @local4 goto o_direct", "goto o_block"])

    def test_rules_before_panel_block_private_ikev2_networks(self):
        """Правила «до панели» ведут частную сеть IKEv2 в блок: туннеля ещё нет, а напрямую сеть недоступна."""
        rules = self._ruleset(self._running_engine(),
                              [{"lists": ["l_company"], "outbound": "up:u000001", "enabled": True}], hold=True)
        policy = policy_chain(rules)
        self.assertIn("ip daddr @local4 ip daddr @l_l_company goto o_block", policy)
        self.assertIn("ip daddr @local4 goto o_direct", policy)

    def _start_with_network(self, engine, resolved: dict | None = None, failed: set | None = None,
                            v6_route: bool = True):
        """Запуск выхода с подменённой сетью сервера показывает, до какого шага он дошёл.

        resolved/failed: итог предварительного разбора имён (_prefetch_hosts).
        v6_route: есть ли в сети сервера маршрут IPv6 к серверу IKEv2.
        Возвращает подменённые цель, runtime, разбор имени и ошибку запуска (None, если запустился).
        """
        import subprocess
        from app import system
        target = mock.Mock(spec=system.Target, key="test-target", pid=42, kind="host")

        def ns(cmd, **kwargs):
            """Только запрос маршрута IPv6 зависит от сценария; остальные команды успешны."""
            rc = 0 if v6_route or cmd[:4] != ["ip", "-6", "route", "get"] else 2
            return subprocess.CompletedProcess(cmd, rc, "[]", "")

        target.ns.side_effect = ns
        runtime = mock.Mock(proc=None)
        engine._pre, engine._pre_failed = resolved or {}, failed or set()
        u = self.st["upstreams"][0]
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(ikev2, "Runtime", return_value=runtime), \
                mock.patch.object(awgconf, "resolve_host", return_value="198.51.100.7") as resolve:
            error = None
            try:
                engine._start_up(target, u["id"], u, awgconf.parse_upstream(u["config"]), "hash")
            except system.SysError as e:
                error = e
        return target, runtime, resolve, error

    @staticmethod
    def _xfrm_created(target) -> bool:
        """Создание XFRM-интерфейса: первое изменение сети сервера при запуске IKEv2."""
        return any(call.args[0][:3] == ["ip", "link", "add"] for call in target.ns.call_args_list)

    def test_ipv6_server_without_route_fails_before_network_changes(self):
        """Сервер IKEv2 по IPv6 без маршрута в сети сервера даёт понятную ошибку, а не вечное ожидание.

        Вход: имя сервера разбирается в IPv6, в сети сервера AWG нет маршрута IPv6.
        Ожидание: SysError sys.no_v6_route; XFRM-интерфейс и charon не запускаются.
        """
        target, runtime, _, error = self._start_with_network(
            Engine(panel_store), resolved={"vpn.example.com": "2001:db8::7"}, v6_route=False)
        self.assertIsNotNone(error)
        self.assertEqual(error.msg.key, "sys.no_v6_route")
        self.assertFalse(self._xfrm_created(target))
        runtime.start.assert_not_called()

    def test_prefetched_server_address_is_used(self):
        """Имя, уже разобранное вместе с другими выходами, второй раз не разбирается."""
        target, runtime, resolve, error = self._start_with_network(
            Engine(panel_store), resolved={"vpn.example.com": "198.51.100.9"})
        self.assertIsNone(error)
        self.assertTrue(self._xfrm_created(target))
        resolve.assert_not_called()
        self.assertEqual(runtime.start.call_args.args[2], "198.51.100.9")

    def test_unresolved_prefetched_name_fails_without_second_wait(self):
        """Неразобранное при общем разборе имя сразу даёт ошибку и не трогает сеть сервера."""
        target, runtime, resolve, error = self._start_with_network(Engine(panel_store), failed={"vpn.example.com"})
        self.assertIsNotNone(error)
        self.assertEqual(error.msg.key, "cfg.endpoint_resolve")
        resolve.assert_not_called()
        self.assertFalse(self._xfrm_created(target))
        runtime.start.assert_not_called()

    def test_names_of_awg_and_ikev2_exits_are_resolved_together(self):
        """Имена серверов IKEv2 разбираются одним вызовом вместе с именами выходов AWG.

        Вход: выход AWG с именем a.example.net и выход IKEv2 с именем vpn.example.com;
        разобралось только первое.
        Ожидание: один вызов resolve_many с обоими именами, имя IKEv2 среди неразобранных.
        """
        from test_v115 import conf
        engine = Engine(panel_store)
        wanted = {"u_awg": {"id": "u_awg", "name": "AWG", "num": 1, "config": conf("a.example.net:51820")},
                  "u_ike": {"id": "u_ike", "name": "IKE", "num": 2, "config": vpn_config()}}
        with mock.patch.object(config, "DRY_RUN", False), \
                mock.patch.object(awgconf, "resolve_many", return_value={"a.example.net": "198.51.100.1"}) as rm:
            engine._prefetch_hosts(wanted, time.time())
        rm.assert_called_once()
        self.assertEqual(sorted(rm.call_args.args[0]), ["a.example.net", "vpn.example.com"])
        self.assertEqual(engine._pre_failed, {"vpn.example.com"})

    def test_names_of_starting_exits_are_resolved_together_while_awg_exits_wait(self):
        """Пока выходы AWG ждут интерфейс сервера, выходы IKEv2 и SOCKS5 запускаются, и их имена разбираются разом.

        Вход: engine_pending истинно; выход AWG, выход SOCKS5 и два выхода IKEv2, все с именами.
        Ожидание: один вызов resolve_many с именами SOCKS5 и IKEv2 без имени AWG; запускаются только
        выходы SOCKS5 и IKEv2.
        """
        from test_v115 import conf
        engine = Engine(panel_store)
        st = {"upstreams": [
            {"id": "u_awg", "name": "AWG", "num": 1, "config": conf("a.example.net:51820")},
            {"id": "u_socks", "name": "Proxy", "num": 2, "config": "socks5://proxy.example.net:1080"},
            {"id": "u_ike1", "name": "IKE 1", "num": 3, "config": vpn_config(host="vpn-a.example.com", remote_id="")},
            {"id": "u_ike2", "name": "IKE 2", "num": 4, "config": vpn_config(host="vpn-b.example.com", remote_id="")},
        ]}
        with mock.patch.object(config, "DRY_RUN", False), mock.patch.object(engine, "_links", return_value=set()), \
                mock.patch.object(engine, "exit_engine", return_value="go"), \
                mock.patch.object(engine, "engine_pending", return_value=True), \
                mock.patch.object(awgconf, "resolve_many", return_value={}) as rm, \
                mock.patch.object(engine, "_start_up") as start:
            engine._sync_upstreams(mock.Mock(key="k", pid=1), st)
        rm.assert_called_once()
        self.assertEqual(sorted(rm.call_args.args[0]), ["proxy.example.net", "vpn-a.example.com", "vpn-b.example.com"])
        self.assertEqual(sorted(call.args[1] for call in start.call_args_list), ["u_ike1", "u_ike2", "u_socks"])

    def test_live_runtime_owner_is_checked_before_network_changes(self):
        """Отказ занять активный выход сохраняет его интерфейс и маршруты."""
        from pathlib import Path
        from app.store import Store
        with tempfile.TemporaryDirectory() as root:
            work = Path(root) / "ike-1"
            work.mkdir()
            owner = b"STRONGSWAN_CONF=" + os.fsencode(str(work / "strongswan.conf"))
            engine = Engine(Store(root + "/state.json"))
            target = mock.Mock(key="target", pid=42)
            target.ns.return_value = mock.Mock(stdout="", stderr="", returncode=0)
            engine.target = target
            upstream = self.st["upstreams"][0]
            files = [mock.mock_open(read_data="123").return_value, mock.mock_open(read_data=owner).return_value]
            with mock.patch("app.engine.tunnels.RUN_DIR", root), mock.patch.object(config, "DRY_RUN", False), \
                    mock.patch.object(awgconf, "resolve_host", return_value="198.51.100.7"), \
                    mock.patch("app.ikev2.open", side_effect=files, create=True):
                with self.assertRaises(ikev2.Ikev2Error):
                    engine._start_up(target, upstream["id"], upstream, engine.parsed(upstream), "hash")
                engine._stop_up(upstream["id"])
            target.ns.assert_not_called()
            self.assertTrue(work.is_dir())

    def test_private_route_diagnostics_follow_ikev2_rules(self):
        """Диагностика частного адреса совпадает с сетевым правилом или основным IKEv2."""
        from app.store import Store
        with tempfile.TemporaryDirectory() as root:
            store = Store(root + "/state.json")
            engine = Engine(store)
            engine.rt["u000001"] = UpRT(1, "hash", "target")
            engine.health["u000001"] = {"healthy": True}
            store.mutate(lambda st: st.update(self.st))
            self.assertEqual(engine.trace(None, "10.55.0.1")["effective"], 1)
            self.st["routing"]["default"] = "direct"
            self.st["routing"]["rules"] = [{"id": "r_company", "lists": ["l0a0b0c"], "outbound": "up:u000001",
                                            "enabled": True}]
            store.mutate(lambda st: st.update(self.st))
            with mock.patch.object(engine.matcher, "contains", return_value="10.55.0.0/16"):
                self.assertEqual(engine.trace(None, "10.55.0.1")["effective"], 1)
            with mock.patch.object(engine.matcher, "contains", return_value=None):
                self.assertEqual(engine.trace(None, "10.56.0.1")["effective"], "direct")

    def test_domain_target_uses_vpn_mark(self):
        """Соединение к сайту получает метку туннеля, а при блокировке не уходит напрямую."""
        with mock.patch.object(panel_engine, "resolve", return_value=1):
            self.assertEqual(panel_engine._sni_target(self.st, "up:u000001"),
                             {"mark": nftgen.mark_for(1), "acct": "u000001"})
        with mock.patch.object(panel_engine, "resolve", return_value="block"):
            self.assertEqual(panel_engine._sni_target(self.st, "up:u000001"), {"block": True})


if __name__ == "__main__":
    unittest.main()
