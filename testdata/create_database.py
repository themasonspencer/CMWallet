import base64
import json
from isomdoc import create_mdoc
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.common import SDObj
from jwcrypto.jwk import JWK
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import load_pem_x509_certificates, load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from helpers import build_claims, build_claims_for_display

mdoc_ds_cert_chain_file = open("testdata/ds_cert_mdoc.pem", "rb").read()
mdoc_ds_cert_chain = load_pem_x509_certificates(mdoc_ds_cert_chain_file)
mdoc_ds_private_key_file = open("testdata/ds_private_key_mdoc.pem", "rb").read()
mdoc_ds_private_key = load_pem_private_key(mdoc_ds_private_key_file, None)

sdjwt_ds_cert_file = open("testdata/ds_cert_sdjwt.pem", "rb").read()
sdjwt_ds_cert = load_pem_x509_certificate(sdjwt_ds_cert_file)
sdjwt_ds_cert_der = sdjwt_ds_cert.public_bytes(encoding=serialization.Encoding.DER)
sdjwt_ds_cert_der_encoded = base64.b64encode(sdjwt_ds_cert_der).decode()
sdjwt_issuer_cert_file = open("testdata/issuer_cert_sdjwt.pem", "rb").read()
sdjwt_issuer_cert = load_pem_x509_certificate(sdjwt_issuer_cert_file)
sdjwt_issuer_cert_der = sdjwt_issuer_cert.public_bytes(encoding=serialization.Encoding.DER)
sdjwt_issuer_cert_der_encoded = base64.b64encode(sdjwt_issuer_cert_der).decode()
sdjwt_ds_private_key_jwk = json.load(open("testdata/ds_private_key_sdjwt.json"))

database_in_json = open("testdata/database_in.json", "rb").read()
database = json.loads(database_in_json)

for cred_id, cred in database.items():
    if cred["format"] == "mso_mdoc":
        mdoc_credential = cred["credential"]
        doctype = mdoc_credential["docType"]
        print("Creating {}".format(doctype))
        claims = []
        mdoc = create_mdoc(doctype, mdoc_ds_cert_chain, mdoc_ds_private_key)
        for namespace, elements in mdoc_credential["nameSpaces"].items():
            for element, value in elements.items():
                path = [namespace, element]
                display = [{"name": value["display"], "locale": "en-US"}]
                claims.append({"path": path, "display": display})
                if element == "portrait":
                    mdoc.add_data_item(namespace, element, base64.urlsafe_b64decode(value["value"]))
                else:
                    mdoc.add_data_item(namespace, element, value["value"])
        cred["claims"] = claims
        device_private_key = ec.generate_private_key(ec.SECP256R1())
        device_public_key = device_private_key.public_key()
        cred["issuerSigned"] = base64.urlsafe_b64encode(
            mdoc.generate_credential(device_public_key)
        ).decode("utf-8")
        cred["deviceKey"] = base64.urlsafe_b64encode(
            device_private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode("utf-8")
        print(cred["deviceKey"])
    elif cred["format"] == "dc+sd-jwt":
        sdjwt_credential = cred["credential"]
        vct = sdjwt_credential["vct"]
        claims = []
        build_claims_for_display(claims, sdjwt_credential["paths"], [])
        cred["claims"] = claims
        user_claims = build_claims(sdjwt_credential["paths"])
        user_claims["vct"] = vct
        device_private_key = ec.generate_private_key(ec.SECP256R1())
        device_public_key = device_private_key.public_key()
        private_numbers = device_private_key.private_numbers()
        public_numbers = device_public_key.public_numbers()
        holder_jwk_public = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64.urlsafe_b64encode(public_numbers.x.to_bytes((public_numbers.x.bit_length() + 7) // 8, 'big')).decode().replace('=', ''),
            "y": base64.urlsafe_b64encode(public_numbers.y.to_bytes((public_numbers.y.bit_length() + 7) // 8, 'big')).decode().replace('=', ''),
        }
        SDJWTIssuer.unsafe_randomness = True
        sdjwt_at_issuer = SDJWTIssuer(
            user_claims=user_claims,
            issuer_keys=JWK.from_json(json.dumps(sdjwt_ds_private_key_jwk)),
            holder_key=JWK.from_json(json.dumps(holder_jwk_public)),
            extra_header_parameters={"typ": "dc+sd-jwt", "x5c": [sdjwt_ds_cert_der_encoded, sdjwt_issuer_cert_der_encoded]}
        )
        cred["issuerSigned"] = sdjwt_at_issuer.sd_jwt_issuance
        cred["deviceKey"] = base64.urlsafe_b64encode(
            device_private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode("utf-8")



with open("testdata/database.json", "w") as f:
    json.dump(database, f, indent=4)
