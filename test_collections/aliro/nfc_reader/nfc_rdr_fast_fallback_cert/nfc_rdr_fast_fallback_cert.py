from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS, ReaderStatus, Transaction
from aliro_actuator.access_protocol.defines import TransportProtocol
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_FAST_FALLBACK_CERT(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_FAST_FALLBACK_CERT",
        "version": "0.0.1",
        "title": "NFC_RDR_FAST_FALLBACK_CERT",
        "description": """Verify that a Reader with a reader_Cert presents it in LOAD CERT or AUTH1 """
        """when an Expedited-fast transaction falls back to Expedited-standard (Aliro 6.3.1).""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePuBK_2 = bytes.fromhex(
        "04e4c78918408463a235923d36e74b71627dabc606f1"
        "b4189af78f755b6e1bf3f7640a7f360130ee4ad268bb"
        "5531878cdce3a3e84da5e2a04efd5e8e4611922f2b"
    )

    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector
    endpoint_ePrivK_2 = bytes.fromhex(
        "a657c9604d5688676c322210a3d73e89fd9fffd7f60044ea9f3a52efc241925d"
    )

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "RD",
                "NFC",
                "RD11",
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set Reader Device Under Test in polling mode"),
            TestStep("Step3: Transaction Initiation Standard"),
            TestStep("Step4: Receive/Send AUTH0 command/response Standard"),
            TestStep("Step5: Receive reader_Cert, Receive/Send AUTH1 command/response Standard"),
            TestStep("Step6: Receive/Send EXCHANGE command/response Standard"),
            TestStep("Step7: Remove Kpersistent from User Device, Transaction Initiation Fast"),
            TestStep("Step8: Receive/Send AUTH0 command/response Fast without Kpersistent"),
            TestStep("Step9: Receive reader_Cert, Receive/Send AUTH1 command/response Fallback"),
            TestStep("Step10: Receive/Send EXCHANGE command/response Fallback"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        self.access_credential = self.reader_access_credential(add_issuer_public_key=True)
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[self.access_credential],
            mailbox=0x20,
            ephemeral_key_list=[
                KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
                KeyPair(self.endpoint_ePrivK_2, self.endpoint_ePuBK_2),
            ],
        )

    async def _handle_cert_and_auth1(self) -> bool:
        """Expect the reader_Cert in LOAD CERT or AUTH1, then handle AUTH1."""
        try:
            command = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        cert_in_load_cert = False
        if command.ins == INS.LOAD_CERT:
            try:
                await self.userdevice.handle_load_cert(command)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return False
            cert_in_load_cert = True

            try:
                command = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return False

        if command.ins != INS.AUTH1:
            self.mark_step_failure(f"Expected AUTH1 command, but received {command.ins}")
            return False

        if not cert_in_load_cert and command.certificate_data is None:
            self.mark_step_failure(
                "Reader did not present reader_Cert in either LOAD CERT or AUTH1 command"
            )
            return False

        logger.info(
            "reader_Cert presented in {}".format("LOAD CERT" if cert_in_load_cert else "AUTH1")
        )

        try:
            await self.userdevice.handle_auth1(command)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False

        if not self.userdevice.session.cert_verified:
            self.mark_step_failure("reader_Cert verification failed")
            return False

        return True

    async def _handle_exchange_until_complete(self) -> bool:
        while True:
            try:
                cmds_exchange = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return False

            if cmds_exchange.ins != INS.EXCHANGE:
                self.mark_step_failure(f"Unexpected command {cmds_exchange.ins}")
                return False

            try:
                await self.userdevice.handle_exchange(cmds_exchange)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return False

            if self.userdevice.session.state_valid(UserSessionState.TRANSACTION_COMPLETE):
                if not ReaderStatus(cmds_exchange.reader_status).is_success:
                    self.mark_step_failure(
                        "Expected Success Reader Status (0x01..), but received {}".format(
                            cmds_exchange.reader_status.name
                        )
                    )
                    return False
                return True

    @log_errors
    async def execute(self) -> None:
        # Test step 1: Initialization
        issuer_group_id = self.access_credential.reader_id_key_list[1][0]
        prompt = "Provision the reader_Cert on the Reader Device Under Test and set its "
        prompt += "reader_group_identifier to: {}\n".format(hexlify(issuer_group_id))
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt=prompt,
                options={"OK": 1},
            )
        )
        self.next_step()

        # Test step 2: Set Reader Device Under Test in polling mode
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode for "
                "standard transaction",
                options={"OK": 1},
            )
        )
        self.next_step()

        # Test step 3: Transaction Initiation Standard
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()  # Including Select
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4: Receive/Send AUTH0 command/response Standard
        try:
            cmds_auth0 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )
            return
        self.next_step()

        # Test step 5: Receive reader_Cert, Receive/Send AUTH1 command/response Standard
        if not await self._handle_cert_and_auth1():
            return
        self.next_step()

        # Test step 6: Receive/Send EXCHANGE command/response Standard
        if not await self._handle_exchange_until_complete():
            return
        self.next_step()

        # Test step 7: Remove Kpersistent from User Device, Transaction Initiation Fast
        # The Reader keeps its Kpersistent and requests Expedited-fast, but the User Device
        # cannot compute the cryptogram, which forces the fallback to Expedited-standard.
        await self.userdevice.transaction_termination()
        self.userdevice.storage.clear_kpersistent()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for fast transaction, \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()  # Including Select
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 8: Receive/Send AUTH0 command/response Fast without Kpersistent
        try:
            cmds_auth0 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if self.userdevice.session.get_transaction_type() != Transaction.FAST:
            self.mark_step_failure("Reader did not request Expedited-fast transaction")
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, a Kpersistent "
                "was unexpectedly found or handling auth0 failed"
            )
            return
        self.next_step()

        # Test step 9: Receive reader_Cert, Receive/Send AUTH1 command/response Fallback
        if not await self._handle_cert_and_auth1():
            return
        self.next_step()

        # Test step 10: Receive/Send EXCHANGE command/response Fallback
        if not await self._handle_exchange_until_complete():
            return

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_FAST_FALLBACK_CERT Cleanup")
        await self.userdevice.transaction_termination()
