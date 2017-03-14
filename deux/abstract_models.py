from __future__ import absolute_import, unicode_literals

from binascii import unhexlify

from django.conf import settings
from django.db import models
from django.utils.crypto import constant_time_compare

from deux.app_settings import mfa_settings
from deux.constants import CHALLENGE_TYPES, DISABLED, SMS
from deux.services import generate_key
from deux.validators import phone_number_validator, country_code_validator


class AbstractMultiFactorAuth(models.Model):
    """
    class::AbstractMultiFactorAuth()

    This abstract class holds user information, MFA status, and secret
    keys for the user.
    """

    #: Different status options for this MFA object.
    CHALLENGE_CHOICES = (
        (SMS, "SMS"),
        (DISABLED, "Off"),
    )

    #: User this MFA object represents.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name="multi_factor_auth",
        primary_key=True)


    phone_country_code = models.CharField(default='+1',
        choices=[('+93', ' Afghanistan'),
             ('+355', ' Albania'),
             ('+213', ' Algeria'),
             ('+684', ' American Samoa'),
             ('+376', ' Andorra'),
             ('+244', ' Angola'),
             ('+809', ' Anguilla'),
             ('+268', ' Antigua'),
             ('+54', ' Argentina'),
             ('+374', ' Armenia'),
             ('+297', ' Aruba'),
             ('+247', ' Ascension Island'),
             ('+61', ' Australia'),
             ('+672', ' Australian External Territories'),
             ('+43', ' Austria'),
             ('+994', ' Azerbaijan'),
             ('+242', ' Bahamas'),
             ('+246', ' Barbados'),
             ('+973', ' Bahrain'),
             ('+880', ' Bangladesh'),
             ('+375', ' Belarus'),
             ('+32', ' Belgium'),
             ('+501', ' Belize'),
             ('+229', ' Benin'),
             ('+809', ' Bermuda'),
             ('+975', ' Bhutan'),
             ('+284', ' British Virgin Islands'),
             ('+591', ' Bolivia'),
             ('+387', ' Bosnia and Hercegovina'),
             ('+267', ' Botswana'),
             ('+55', ' Brazil'),
             ('+284', ' British V.I.'),
             ('+673', ' Brunei Darussalm'),
             ('+359', ' Bulgaria'),
             ('+226', ' Burkina Faso'),
             ('+257', ' Burundi'),
             ('+855', ' Cambodia'),
             ('+237', ' Cameroon'),
             ('+1', ' Canada'),
             ('+238', ' CapeVerde Islands'),
             ('+1', ' Caribbean Nations'),
             ('+345', ' Cayman Islands'),
             ('+238', ' Cape Verdi'),
             ('+236', ' Central African Republic'),
             ('+235', ' Chad'),
             ('+56', ' Chile'),
             ('+86', " China (People's Republic)"),
             ('+886', ' China-Taiwan'),
             ('+57', ' Colombia'),
             ('+269', ' Comoros and Mayotte'),
             ('+242', ' Congo'),
             ('+682', ' Cook Islands'),
             ('+506', ' Costa Rica'),
             ('+385', ' Croatia'),
             ('+53', ' Cuba'),
             ('+357', ' Cyprus'),
             ('+420', ' Czech Republic'),
             ('+45', ' Denmark'),
             ('+246', ' Diego Garcia'),
             ('+767', ' Dominca'),
             ('+809', ' Dominican Republic'),
             ('+253', ' Djibouti'),
             ('+593', ' Ecuador'),
             ('+20', ' Egypt'),
             ('+503', ' El Salvador'),
             ('+240', ' Equatorial Guinea'),
             ('+291', ' Eritrea'),
             ('+372', ' Estonia'),
             ('+251', ' Ethiopia'),
             ('+500', ' Falkland Islands'),
             ('+298', ' Faroe (Faeroe) Islands (Denmark)'),
             ('+679', ' Fiji'),
             ('+358', ' Finland'),
             ('+33', ' France'),
             ('+596', ' French Antilles'),
             ('+594', ' French Guiana'),
             ('+241', ' Gabon (Gabonese Republic)'),
             ('+220', ' Gambia'),
             ('+995', ' Georgia'),
             ('+49', ' Germany'),
             ('+233', ' Ghana'),
             ('+350', ' Gibraltar'),
             ('+30', ' Greece'),
             ('+299', ' Greenland'),
             ('+473', ' Grenada/Carricou'),
             ('+671', ' Guam'),
             ('+502', ' Guatemala'),
             ('+224', ' Guinea'),
             ('+245', ' Guinea-Bissau'),
             ('+592', ' Guyana'),
             ('+509', ' Haiti'),
             ('+504', ' Honduras'),
             ('+852', ' Hong Kong'),
             ('+36', ' Hungary'),
             ('+354', ' Iceland'),
             ('+91', ' India'),
             ('+62', ' Indonesia'),
             ('+98', ' Iran'),
             ('+964', ' Iraq'),
             ('+353', ' Ireland (Irish Republic; Eire)'),
             ('+972', ' Israel'),
             ('+39', ' Italy'),
             ('+225', " Ivory Coast (La Cote d'Ivoire)"),
             ('+876', ' Jamaica'),
             ('+81', ' Japan'),
             ('+962', ' Jordan'),
             ('+7', ' Kazakhstan'),
             ('+254', ' Kenya'),
             ('+855', ' Khmer Republic (Cambodia/Kampuchea)'),
             ('+686', ' Kiribati Republic (Gilbert Islands)'),
             ('+82', ' Korea, Republic of (South Korea)'),
             ('+850', " Korea, People's Republic of (North Korea)"),
             ('+965', ' Kuwait'),
             ('+996', ' Kyrgyz Republic'),
             ('+371', ' Latvia'),
             ('+856', ' Laos'),
             ('+961', ' Lebanon'),
             ('+266', ' Lesotho'),
             ('+231', ' Liberia'),
             ('+370', ' Lithuania'),
             ('+218', ' Libya'),
             ('+423', ' Liechtenstein'),
             ('+352', ' Luxembourg'),
             ('+853', ' Macao'),
             ('+389', ' Macedonia'),
             ('+261', ' Madagascar'),
             ('+265', ' Malawi'),
             ('+60', ' Malaysia'),
             ('+960', ' Maldives'),
             ('+223', ' Mali'),
             ('+356', ' Malta'),
             ('+692', ' Marshall Islands'),
             ('+596', ' Martinique (French Antilles)'),
             ('+222', ' Mauritania'),
             ('+230', ' Mauritius'),
             ('+269', ' Mayolte'),
             ('+52', ' Mexico'),
             ('+691', ' Micronesia (F.S. of Polynesia)'),
             ('+373', ' Moldova'),
             ('+33', ' Monaco'),
             ('+976', ' Mongolia'),
             ('+473', ' Montserrat'),
             ('+212', ' Morocco'),
             ('+258', ' Mozambique'),
             ('+95', ' Myanmar (former Burma)'),
             ('+264', ' Namibia (former South-West Africa)'),
             ('+674', ' Nauru'),
             ('+977', ' Nepal'),
             ('+31', ' Netherlands'),
             ('+599', ' Netherlands Antilles'),
             ('+869', ' Nevis'),
             ('+687', ' New Caledonia'),
             ('+64', ' New Zealand'),
             ('+505', ' Nicaragua'),
             ('+227', ' Niger'),
             ('+234', ' Nigeria'),
             ('+683', ' Niue'),
             ('+850', ' North Korea'),
             ('+1670', ' North Mariana Islands (Saipan)'),
             ('+47', ' Norway'),
             ('+968', ' Oman'),
             ('+92', ' Pakistan'),
             ('+680', ' Palau'),
             ('+507', ' Panama'),
             ('+675', ' Papua New Guinea'),
             ('+595', ' Paraguay'),
             ('+51', ' Peru'),
             ('+63', ' Philippines'),
             ('+48', ' Poland'),
             ('+351', ' Portugal (includes Azores)'),
             ('+1787', ' Puerto Rico'),
             ('+974', ' Qatar'),
             ('+262', ' Reunion (France)'),
             ('+40', ' Romania'),
             ('+7', ' Russia'),
             ('+250', ' Rwanda (Rwandese Republic)'),
             ('+670', ' Saipan'),
             ('+378', ' San Marino'),
             ('+239', ' Sao Tome and Principe'),
             ('+966', ' Saudi Arabia'),
             ('+221', ' Senegal'),
             ('+381', ' Serbia and Montenegro'),
             ('+248', ' Seychelles'),
             ('+232', ' Sierra Leone'),
             ('+65', ' Singapore'),
             ('+421', ' Slovakia'),
             ('+386', ' Slovenia'),
             ('+677', ' Solomon Islands'),
             ('+252', ' Somalia'),
             ('+27', ' South Africa'),
             ('+34', ' Spain'),
             ('+94', ' Sri Lanka'),
             ('+290', ' St. Helena'),
             ('+869', ' St. Kitts/Nevis'),
             ('+508', ' St. Pierre &(et) Miquelon (France)'),
             ('+249', ' Sudan'),
             ('+597', ' Suriname'),
             ('+268', ' Swaziland'),
             ('+46', ' Sweden'),
             ('+41', ' Switzerland'),
             ('+963', ' Syrian Arab Republic (Syria)'),
             ('+689', ' Tahiti (French Polynesia)'),
             ('+886', ' Taiwan'),
             ('+7', ' Tajikistan'),
             ('+255', ' Tanzania (includes Zanzibar)'),
             ('+66', ' Thailand'),
             ('+228', ' Togo (Togolese Republic)'),
             ('+690', ' Tokelau'),
             ('+676', ' Tonga'),
             ('+1868', ' Trinidad and Tobago'),
             ('+216', ' Tunisia'),
             ('+90', ' Turkey'),
             ('+993', ' Turkmenistan'),
             ('+688', ' Tuvalu (Ellice Islands)'),
             ('+256', ' Uganda'),
             ('+380', ' Ukraine'),
             ('+971', ' United Arab Emirates'),
             ('+44', ' United Kingdom'),
             ('+598', ' Uruguay'),
             ('+1', ' USA'),
             ('+7', ' Uzbekistan'),
             ('+678', ' Vanuatu (New Hebrides)'),
             ('+39', ' Vatican City'),
             ('+58', ' Venezuela'),
             ('+84', ' Viet Nam'),
             ('+1340', ' Virgin Islands'),
             ('+681', ' Wallis and Futuna'),
             ('+685', ' Western Samoa'),
             ('+381', " Yemen (People's Democratic Republic of)"),
             ('+967', ' Yemen Arab Republic (North Yemen)'),
             ('+381', ' Yugoslavia (discontinued)'),
             ('+243', ' Zaire'),
             ('+260', ' Zambia'),
             ('+263', ' Zimbabwe')],
        max_length=5,
        validators=[country_code_validator]
    )

    #: User's phone number.
    phone_number = models.CharField(
        max_length=15, default="", blank=True,
        validators=[phone_number_validator])


    #: Challenge type used for MFA.
    challenge_type = models.CharField(
        max_length=16, default=DISABLED,
        blank=True, choices=CHALLENGE_CHOICES
    )

    #: Secret key used for backup code.
    backup_key = models.CharField(
        max_length=32, default="", blank=True,
        help_text="Hex-Encoded Secret Key"
    )

    #: Secret key used for SMS codes.
    sms_secret_key = models.CharField(
        max_length=32, default=generate_key,
        help_text="Hex-Encoded Secret Key"
    )

    @property
    def full_number(self):
        return self.phone_country_code + self.phone_number

    @property
    def sms_bin_key(self):
        """Returns binary data of the SMS secret key."""
        return unhexlify(self.sms_secret_key)

    @property
    def enabled(self):
        """Returns if MFA is enabled."""
        return self.challenge_type in CHALLENGE_TYPES

    @property
    def backup_code(self):
        """Returns the users backup code."""
        return self.backup_key.upper()[:mfa_settings.BACKUP_CODE_DIGITS]

    def get_bin_key(self, challenge_type):
        """
        Returns the key associated with the inputted challenge type.

        :param challenge_type: The challenge type the key is requested for.
                               The type must be in the supported
                               `CHALLENGE_TYPES`.
        :raises AssertionError: If ``challenge_type`` is not a supported
                                challenge type.
        """
        assert challenge_type in CHALLENGE_TYPES, (
            "'{challenge}' is not a valid challenge type.".format(
                challenge=challenge_type)
        )
        return {
            SMS: self.sms_bin_key
        }.get(challenge_type, None)

    def enable(self, challenge_type):
        """
        Enables MFA for this user with the inputted challenge type.

        The enabling process includes setting this objects challenge type and
        generating a new backup key.

        :param challenge_type: Enable MFA for this type of challenge. The type
                               must be in the supported `CHALLENGE_TYPES`.
        :raises AssertionError: If ``challenge_type`` is not a supported
                                challenge type.
        """
        assert challenge_type in CHALLENGE_TYPES, (
            "'{challenge}' is not a valid challenge type.".format(
                challenge=challenge_type)
        )
        self.challenge_type = challenge_type
        self.backup_key = generate_key()
        self.save()

    def disable(self):
        """
        Disables MFA for this user.

        The disabling process includes setting the objects challenge type to
        `DISABLED`, and removing the `backup_key` and `phone_number`.
        """
        self.challenge_type = DISABLED
        self.backup_key = ""
        self.phone_number = ""
        self.save()

    def refresh_backup_code(self):
        """
        Refreshes the users backup key and returns a new backup code.

        This method should be used to request new backup codes for the user.
        """
        assert self.enabled, (
            "MFA must be on to run refresh_backup_codes."
        )
        self.backup_key = generate_key()
        self.save()
        return self.backup_code

    def check_and_use_backup_code(self, code):
        """
        Checks if the inputted backup code is correct and disables MFA if
        the code is correct.

        This method should be used for authenticating with a backup code. Using
        a backup code to authenticate disables MFA as a side effect.
        """
        backup = self.backup_code
        if code and constant_time_compare(code, backup):
            self.disable()
            return True
        return False

    class Meta:
        abstract = True
