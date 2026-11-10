from django.db import models

from uploadshield.django import FileValidator


class Document(models.Model):
    title = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to="docs/", validators=[FileValidator("pdf")])

    class Meta:
        app_label = "testapp"

    def __str__(self) -> str:
        return str(self.title)
