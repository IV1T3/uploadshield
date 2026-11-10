from uploadshield import Policy

CUSTOM = Policy(name="custom", allowed_types={"text/plain"})
ZIPS = Policy(name="zips", allowed_types={"application/zip"})
NOT_A_POLICY = "just a string"


def teapot_handler(request, validation):
    from django.http import HttpResponse

    return HttpResponse(f"teapot:{len(validation.rejected)}", status=418)
