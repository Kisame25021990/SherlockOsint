from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from app.modules.base import BaseModule, ModuleContext, ModuleReport, make_finding


class PhoneModule(BaseModule):
    name = "phone"
    label = "Téléphone"
    description = "Validation, pays, opérateur et type de ligne"
    hint = "ex: +33 6 12 34 56 78"

    def run(self, ctx: ModuleContext) -> ModuleReport:
        raw = ctx.target
        try:
            number = phonenumbers.parse(raw, None)
        except phonenumbers.NumberParseException as exc:
            raise ValueError(f"Numéro invalide : {exc}") from exc

        possible = phonenumbers.is_possible_number(number)
        valid = phonenumbers.is_valid_number(number)
        ctx.progress(0, 2)
        make_finding(
            ctx,
            kind="validation",
            label="Numéro",
            value=phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            detail="Valide" if valid else "Possible mais invalide" if possible else "Impossible",
            status="found" if valid else "warning",
            data={
                "valid": valid,
                "possible": possible,
                "e164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
            },
        )

        region = phonenumbers.region_code_for_number(number) or "Inconnue"
        line_type = phonenumbers.number_type(number)
        line_label = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixe",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixe ou mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Numéro gratuit",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Numéro surtaxé",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.SHARED_COST: "Coût partagé",
        }.get(line_type, "Inconnu")
        operator = carrier.name_for_number(number, "fr") or "Inconnu"
        location = geocoder.description_for_number(number, "fr") or "Inconnue"
        zones = timezone.time_zones_for_number(number)

        make_finding(
            ctx,
            kind="identity",
            label="Détails",
            value=f"{region} · {line_label}",
            status="info",
            detail=f"Opérateur : {operator} · Zone : {location}",
            data={
                "region": region,
                "line_type": line_label,
                "carrier": operator,
                "location": location,
                "timezones": list(zones),
            },
        )
        ctx.progress(2, 2)
        return ModuleReport(metadata={"region": region, "valid": valid})
