import datetime

from aliro_actuator.access_protocol.apdu import (
    INS,
    ReaderStatus,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.common import IssuerNamespaces, DocTypes
from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.mdl.response import DeviceResponse
from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.response.device_response_builder import DeviceResponseBuilder, ResponseElement
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_STEPUP_FAST(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_STEPUP_FAST",
        "version": "0.0.1",
        "title": "NFC_RDR_STEPUP_FAST",
        "description": """Verify conformance of Reader UT in Step-Up Transaction followed by Expedited-Fast Transaction, with validity iteration handling.""",
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

    # Access Credential B keypair
    access_credential_B_PuBK = bytes.fromhex(
        "0400ADBB74BBBB7E06B0A28C7D049B023796CD0F7CB9"
        "E279EC42ECFE6E415842451EB93AC5BF62D25CC1DAEA"
        "898A82B18BD813A061E21CB58B3CA93DA6DC7EC300"
    )
    access_credential_B_PrivK = bytes.fromhex(
        "63BD7CE2A4ED2C35232E2C642851F3E22E6F274E1F164CA3B4D32CCA18B51FFE"
    )

    # Validity iterations
    VALIDITY_ITERATION_A1 = 1      # First document for Credential A
    VALIDITY_ITERATION_B = 11     # Document for Credential B (A1 + 10)
    VALIDITY_ITERATION_A2 = 12    # Second document for Credential A (B + 1)

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "RD",
                "NFC",
                "RD11",
                "RD24",
                "RD28"
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set Reader Device Under Test in polling mode"),
            # Credential A - Step-up transaction (first document)
            TestStep("Step3: Transaction Initiation Step-Up (Credential A)"),
            TestStep("Step4: Receive/Send AUTH0 command/response Step-Up (Credential A)"),
            TestStep("Step5: Receive/Send AUTH1 command/response Step-Up (Credential A)"),
            TestStep("Step6: Handle Step-up SELECT (Credential A)"),
            TestStep("Step7: Handle ENVELOPE command/response (Credential A)"),
            TestStep("Step8: Handle EXCHANGE command/response Step-Up (Credential A)"),
            # Credential A - Fast transaction
            TestStep("Step9: Transaction Initiation Fast (Credential A)"),
            TestStep("Step10: Receive/Send AUTH0 command/response Fast (Credential A)"),
            TestStep("Step11: Receive/Send EXCHANGE command/response Fast (Credential A)"),
            # Credential B - Step-up transaction (higher validity iteration)
            TestStep("Step12: Transaction Initiation Step-Up (Credential B)"),
            TestStep("Step13: Receive/Send AUTH0 command/response Step-Up (Credential B)"),
            TestStep("Step14: Receive/Send AUTH1 command/response Step-Up (Credential B)"),
            TestStep("Step15: Handle Step-up SELECT (Credential B)"),
            TestStep("Step16: Handle ENVELOPE command/response (Credential B)"),
            TestStep("Step17: Handle EXCHANGE command/response Step-Up (Credential B)"),
            # Credential B - Fast transaction
            TestStep("Step18: Transaction Initiation Fast (Credential B)"),
            TestStep("Step19: Receive/Send AUTH0 command/response Fast (Credential B)"),
            TestStep("Step20: Receive/Send EXCHANGE command/response Fast (Credential B)"),
            # Credential A - Fast to Standard fallback with Step-up (second document, higher validity iteration)
            TestStep("Step21: Transaction Initiation (Credential A - Fallback)"),
            TestStep("Step22: Receive/Send AUTH0 command/response Fast (Credential A - Fallback)"),
            TestStep("Step23: Receive/Send AUTH1 command/response Standard (Credential A - Fallback)"),
            TestStep("Step24: Handle Step-up SELECT (Credential A - Fallback)"),
            TestStep("Step25: Handle ENVELOPE command/response (Credential A - Fallback)"),
            TestStep("Step26: Receive/Send EXCHANGE command/response Standard (Credential A - Fallback)"),
        ]

    def build_access_document(
        self,
        access_credential_pk: bytes,
        validity_iteration: int,
        signed_time: datetime.datetime
    ) -> bytes:
        issuer_keypair, _, self.element_id = self.access_document_data()

        access_element = AccessData()
        access_element.version = 1

        x = DeviceResponseBuilder.build_doc(
            doc_type=DocTypes.ALIRO_ACCESS,
            namespace=IssuerNamespaces.ALIRO_ACCESS,
            data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
            issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
            device_public_key=access_credential_pk,
            valid_from=signed_time,
            valid_until=signed_time + datetime.timedelta(days=14),
            validity_iteration=validity_iteration,
            signed=signed_time,
        ).to_cbor()

        logger.info(f"Generated Access Document (validity_iteration={validity_iteration}, signed={signed_time}): {x.hex()}")
        return x

    async def setup(self) -> None:
        logger.info("This is a test case setup")

        # Base time for document signing - each document will be 1 second apart
        base_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=3)

        # Access Credential A (from configuration)
        self.access_credential_A = self.reader_access_credential(use_random_ud_keypair=True)

        # First Access Document for Credential A (validity_iteration = 1)
        access_doc_A1 = self.build_access_document(
            self.access_credential_A.get_access_credential_public_key().as_bytes(),
            self.VALIDITY_ITERATION_A1,
            signed_time=base_time
        )

        # Access Credential B (hardcoded keypair)
        access_credential_B = AccessCredential(
            access_credential_key_pair=KeyPair(
                self.access_credential_B_PrivK, self.access_credential_B_PuBK
            ),
            reader_id_key_list=self.access_credential_A.reader_id_key_list
        )

        # Access Document for Credential B (validity_iteration = 11)
        access_doc_B = self.build_access_document(
            access_credential_B.get_access_credential_public_key().as_bytes(),
            self.VALIDITY_ITERATION_B,
            signed_time=base_time + datetime.timedelta(seconds=1)
        )

        # Second Access Document for Credential A (validity_iteration = 12, higher than B)
        self.access_doc_A2 = self.build_access_document(
            self.access_credential_A.get_access_credential_public_key().as_bytes(),
            self.VALIDITY_ITERATION_A2,
            signed_time=base_time + datetime.timedelta(seconds=2)
        )

        # UserDevice for Credential A (initially with first document)
        self.userdevice_A = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[self.access_credential_A],
            mailbox=0x20,
            ephemeral_key_list=[
                KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
                KeyPair(self.endpoint_ePrivK_2, self.endpoint_ePuBK_2),
            ],
            access_document=access_doc_A1,
            step_up_aid_required=True,
        )

        # UserDevice for Credential B
        self.userdevice_B = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential_B],
            mailbox=0x20,
            ephemeral_key_list=[
                KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
                KeyPair(self.endpoint_ePrivK_2, self.endpoint_ePuBK_2),
            ],
            access_document=access_doc_B,
            step_up_aid_required=True,
        )

        # Set current userdevice for cleanup
        self.userdevice = self.userdevice_A

    async def _do_stepup_transaction(self, userdevice: UserDevice, credential_name: str) -> bool:
        """Perform a Step-Up transaction. Returns True on success, False on failure."""
        # Transaction Initiation
        try:
            await userdevice.transaction_initiation()
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # AUTH0
        try:
            cmds_auth0 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        if not userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )
            return False
        self.next_step()

        # AUTH1
        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # Step-up SELECT
        try:
            cmds_select = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_select(cmds_select)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # ENVELOPE
        try:
            cmds_envelope = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        # Verify device request
        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
            self.mark_step_failure("Failed to parse device request.")
            return False

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return False

        found_element = False
        for doc_type, elm_req in [y for x in device_request.doc_requests for y in
                                  x.items_request.namespaces.data.items()]:
            if doc_type != "aliro-a":
                continue
            if self.element_id in elm_req.keys():
                found_element = True

        if not found_element:
            self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
            return False

        try:
            await userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # EXCHANGE
        try:
            cmds_exchange = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        try:
            await userdevice.handle_exchange(cmds_exchange)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False

        if cmds_exchange.reader_status.value.to_bytes(2, 'big')[0] != 0x01:
            self.mark_step_failure(
                "Received incorrect EXCHANGE reader status: 0x{:04x}".format(
                    cmds_exchange.reader_status.value
                )
            )
            return False
        self.next_step()

        return True

    async def _do_fast_transaction(self, userdevice: UserDevice, credential_name: str) -> bool:
        """Perform a Fast transaction. Returns True on success, False on failure."""
        # Transaction Initiation
        try:
            await userdevice.transaction_initiation()
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # AUTH0 (Fast)
        try:
            cmds_auth0 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        if not userdevice.session.state_valid(UserSessionState.AUTH0_FAST_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 fast done, either standard "
                "transaction was requested or handling auth0 failed"
            )
            return False
        self.next_step()

        # EXCHANGE (Fast)
        while True:
            try:
                cmds_exchange = await userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return False

            if cmds_exchange.ins == INS.EXCHANGE:
                try:
                    await userdevice.handle_exchange(cmds_exchange)
                except AccessProtocolError as error:
                    self.mark_step_failure(str(error))
                    return False

                if userdevice.session.state_valid(UserSessionState.TRANSACTION_COMPLETE):
                    if not ReaderStatus(cmds_exchange.reader_status).is_success:
                        self.mark_step_failure(
                            "Expected Success Reader Status (0x01..), but received {}".format(
                                cmds_exchange.reader_status.name
                            )
                        )
                        return False
                    else:
                        break
            else:
                self.mark_step_failure(f"Unexpected command {cmds_exchange.ins}")
                return False

        self.next_step()
        return True

    async def _do_fast_to_standard_fallback_with_stepup_transaction(
        self,
        userdevice: UserDevice,
        credential_name: str
    ) -> bool:
        """
        Perform a transaction that starts as Fast but falls back to Standard with Step-Up
        due to outdated validity iteration. Uses a new Access Document with higher validity iteration.
        """
        # Transaction Initiation
        try:
            await userdevice.transaction_initiation()
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # AUTH0 - UserDevice expects Fast (has kPersistent), but reader will force Standard
        try:
            cmds_auth0 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False

        # Check that AUTH0 indicates fast capability (UserDevice has kPersistent)
        if not userdevice.session.state_valid(UserSessionState.AUTH0_FAST_DONE):
            self.mark_step_failure(
                f"Userdevice ({credential_name}) is not in state auth0 fast done. "
                "Expected fast capability due to existing kPersistent."
            )
            return False
        self.next_step()

        # AUTH1 - Reader forces Standard transaction due to outdated validity iteration
        try:
            cmds_auth1 = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        if cmds_auth1.ins != INS.AUTH1:
            self.mark_step_failure(
                f"Expected AUTH1 command (reader forcing standard), but received {cmds_auth1.ins}"
            )
            return False

        try:
            await userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # Step-up SELECT
        try:
            cmds_select = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False
        try:
            await userdevice.handle_select(cmds_select)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # ENVELOPE (with new Access Document that has higher validity iteration)
        try:
            cmds_envelope = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        # Verify device request
        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
            self.mark_step_failure("Failed to parse device request.")
            return False

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return False

        found_element = False
        for doc_type, elm_req in [y for x in device_request.doc_requests for y in
                                  x.items_request.namespaces.data.items()]:
            if doc_type != "aliro-a":
                continue
            if self.element_id in elm_req.keys():
                found_element = True

        if not found_element:
            self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
            return False

        try:
            await userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return False
        self.next_step()

        # EXCHANGE (Standard)
        try:
            cmds_exchange = await userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return False

        if cmds_exchange.ins == INS.EXCHANGE:
            try:
                await userdevice.handle_exchange(cmds_exchange)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return False

            if cmds_exchange.reader_status.value.to_bytes(2, 'big')[0] != 0x01:
                self.mark_step_failure(
                    "Received incorrect EXCHANGE reader status: 0x{:04x}".format(
                        cmds_exchange.reader_status.value
                    )
                )
                return False
        else:
            self.mark_step_failure(f"Expected EXCHANGE command, but received {cmds_exchange.ins}")
            return False

        self.next_step()
        return True

    @log_errors
    async def execute(self) -> None:
        # Test step 1: Initialization
        # Done in setup
        self.next_step()

        # Test Step 2: Set Reader Device Under Test in polling mode
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode for "
                "step-up transaction (Credential A)",
                options={"OK": 1},
            )
        )
        self.next_step()

        # =====================================================
        # Credential A - Step-up transaction (Steps 3-8)
        # First Access Document with validity_iteration = 1
        # =====================================================
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        self.userdevice = self.userdevice_A
        if not await self._do_stepup_transaction(self.userdevice_A, "Credential A"):
            return

        # =====================================================
        # Credential A - Fast transaction (Steps 9-11)
        # =====================================================
        await self.userdevice_A.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for fast transaction (Credential A), \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        if not await self._do_fast_transaction(self.userdevice_A, "Credential A"):
            return

        # =====================================================
        # Credential B - Step-up transaction (Steps 12-17)
        # Access Document with validity_iteration = 11
        # =====================================================
        await self.userdevice_A.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for step-up transaction (Credential B), \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_B
        if not await self._do_stepup_transaction(self.userdevice_B, "Credential B"):
            return

        # =====================================================
        # Credential B - Fast transaction (Steps 18-20)
        # =====================================================
        await self.userdevice_B.transaction_termination()
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for fast transaction (Credential B), \r\nand bring Test "
                "Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        if not await self._do_fast_transaction(self.userdevice_B, "Credential B"):
            return

        # =====================================================
        # Credential A - Fast to Standard fallback with Step-up (Steps 21-26)
        # Update UserDevice A with second Access Document (validity_iteration = 12)
        # Reader should force standard due to outdated validity iteration
        # =====================================================
        await self.userdevice_B.transaction_termination()

        # Update UserDevice A with the second Access Document (higher validity iteration)
        self.userdevice_A.access_document = self.access_doc_A2

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Remove Test Harness, set Reader Device Under Test in "
                "NFC polling mode for transaction (Credential A - Fallback with new document), "
                "\r\nand bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        self.userdevice = self.userdevice_A
        if not await self._do_fast_to_standard_fallback_with_stepup_transaction(
            self.userdevice_A, "Credential A"
        ):
            return

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_STEPUP_FAST Cleanup")
        await self.userdevice.transaction_termination()
