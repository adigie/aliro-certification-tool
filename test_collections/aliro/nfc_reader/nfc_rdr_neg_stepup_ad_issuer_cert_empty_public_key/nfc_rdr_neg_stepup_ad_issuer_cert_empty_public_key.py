import base64
import datetime

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

from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.common import DocTypes, IssuerNamespaces
from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.mdl.response.device_response_builder import (
    DeviceResponseBuilder,
    ResponseElement,
)
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_NEG_STEPUP_AD_ISSUER_CERT_EMPTY_PUBLIC_KEY(
    AliroReaderTestCase, UserPromptSupport
):
    metadata = {
        "public_id": "NFC_RDR_NEG_STEPUP_AD_ISSUER_CERT_EMPTY_PUBLIC_KEY",
        "version": "0.0.1",
        "title": "NFC_RDR_NEG_STEPUP_AD_ISSUER_CERT_EMPTY_PUBLIC_KEY",
        "description": (
            "Verify rejection of an Access Document whose issuer certificate "
            "contains an empty EC public key"
        ),
    }

    issuer_certificate_pem = b"""-----BEGIN CERTIFICATE-----
MIHlMIHLoAMCAQICASowCgYIKoZIzj0EAwIwIzEhMB8GA1UEAxMYQ1ZFLTIwMjYtNTA1ODMgSXNz
dWVyIENBMB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowITEfMB0GA1UEAxMWQ1ZFLTIw
MjYtNTA1ODMgU3ViamVjdDAYMBMGByqGSM49AgEGCCqGSM49AwEHAwEAozMwMTAfBgNVHSMEGDAW
gBSai3xtXk8BAgMEBQYHCAkKCwwNDjAOBgNVHQ8BAf8EBAMCAoQwCgYIKoZIzj0EAwIDCQAwBgIB
AAIBAA==
-----END CERTIFICATE-----"""

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )

    @classmethod
    def pics(cls) -> set[str]:
        return {"RD", "NFC", "RD26"}

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Perform Expedited Standard transaction"),
            TestStep("Step2: Handle ENVELOPE command/response"),
            TestStep("Step3: Handle EXCHANGE command/response"),
        ]

    @classmethod
    def issuer_certificate_der(cls) -> bytes:
        pem_body = b"".join(cls.issuer_certificate_pem.splitlines()[1:-1])
        return base64.b64decode(pem_body, validate=True)

    def build_access_document(self, access_credential_pk: bytes) -> bytes:
        issuer_keypair, _, self.element_id = self.access_document_data()

        access_element = AccessData()
        access_element.version = 1

        access_document = DeviceResponseBuilder.build_doc(
            doc_type=DocTypes.ALIRO_ACCESS,
            namespace=IssuerNamespaces.ALIRO_ACCESS,
            data_elements=[
                ResponseElement(
                    data_element_id=self.element_id,
                    value=access_element,
                )
            ],
            issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
            device_public_key=access_credential_pk,
            valid_from=datetime.datetime.now(datetime.timezone.utc),
            valid_until=(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=14)
            ),
            x509_cert=self.issuer_certificate_der(),
            use_keyId=False,
        ).to_cbor()

        logger.info(f"Generated Access Document: {access_document.hex()}")
        return access_document

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential = self.reader_access_credential(use_random_ud_keypair=True)
        access_doc = self.build_access_document(
            access_credential.get_access_credential_public_key().as_bytes()
        )

        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=None,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            access_document=access_doc,
        )

    @log_errors
    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )

        try:
            await self.userdevice.transaction_initiation()
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return

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

        try:
            cmds_auth1 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return

        try:
            await self.userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        try:
            cmds_envelope = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return

        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
            self.mark_step_failure("Failed to parse device request.")
            return

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return

        found_element = any(
            self.element_id in element_requests
            for doc_request in device_request.doc_requests
            for doc_type, element_requests in doc_request.items_request.namespaces.data.items()
            if doc_type == DocTypes.ALIRO_ACCESS
        )
        if not found_element:
            self.mark_step_failure(
                f"Reader did not request Element ID {self.element_id}"
            )
            return

        try:
            await self.userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        try:
            cmds_exchange = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return

        try:
            await self.userdevice.handle_exchange(cmds_exchange)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return

        if cmds_exchange.reader_status.value.to_bytes(2, "big")[0] != 0x00:
            self.mark_step_failure(
                "Received incorrect EXCHANGE reader status: 0x{:04x}".format(
                    cmds_exchange.reader_status.value
                )
            )

    async def cleanup(self) -> None:
        logger.info(
            "NFC_RDR_NEG_STEPUP_AD_ISSUER_CERT_EMPTY_PUBLIC_KEY Cleanup"
        )
        await self.userdevice.transaction_termination()
