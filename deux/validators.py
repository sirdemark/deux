from __future__ import absolute_import, unicode_literals

from django.core.validators import RegexValidator

from deux import strings

#: Regex validator for country code.
country_code_validator = RegexValidator(
    regex=r"^(\+?\d{1,4})$",
    message=strings.INVALID_COUNTRY_CODE_ERROR)


#: Regex validator for phone numbers.
phone_number_validator = RegexValidator(
    regex=r"^(\d{7,15})$",
    message=strings.INVALID_PHONE_NUMBER_ERROR)
