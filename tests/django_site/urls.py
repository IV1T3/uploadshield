import importlib.util

from django.urls import path

from tests.django_site.testapp import views

handler400 = "uploadshield.django.views.bad_request"

urlpatterns = [
    path("plain/", views.plain, name="plain"),
    path("images/", views.images, name="images"),
    path("avatar/", views.avatar, name="avatar"),
    path("multi/", views.multi, name="multi"),
    path("raw/", views.raw, name="raw"),
    path("report/", views.report, name="report"),
    path("redirecting/", views.redirecting, name="redirecting"),
    path("bare/", views.bare, name="bare"),
    path("tiny/", views.tiny, name="tiny"),
    path("async-images/", views.async_images, name="async-images"),
    path("pdf-view/", views.PdfView.as_view(), name="pdf-view"),
    path("async-image-view/", views.AsyncImageView.as_view(), name="async-image-view"),
    path("form/", views.form_view, name="form"),
    path("model-form/", views.model_form_view, name="model-form"),
    path("legacy/upload/", views.plain, name="legacy-upload"),
    path("unprotected/", views.plain, name="unprotected-upload"),
    path("done/", views.done, name="done"),
    path("stacked/", views.stacked, name="stacked"),
    path("field-mode/", views.field_mode, name="field-mode"),
    path("kinds/", views.kinds, name="kinds"),
    path("store/", views.store, name="store"),
    path("store-checked/", views.store_checked, name="store-checked"),
    path("suspicious/", views.suspicious, name="suspicious"),
    path("method-view/", views.MethodDecoratedView.as_view(), name="method-view"),
    path("rename/", views.rename_and_store, name="rename"),
    path("csrf-zip/", views.CsrfProtectedZipView.as_view(), name="csrf-zip"),
    path("method-on-reject/", views.MethodOnRejectView.as_view(), name="method-on-reject"),
]

if importlib.util.find_spec("rest_framework"):
    from tests.django_site.testapp import api

    urlpatterns += [
        path("api/documents/", api.DocumentAPI.as_view(), name="api-documents"),
        path("api/raw/<str:filename>", api.RawUploadAPI.as_view(), name="api-raw"),
        path("api/serializer/", api.SerializerAPI.as_view(), name="api-serializer"),
        path("api/function/", api.document_function, name="api-function"),
        path("api/method/", api.MethodDecoratedAPI.as_view(), name="api-method"),
        path("api/raw-field/<str:filename>", api.RawFieldAPI.as_view(), name="api-raw-field"),
        path("api/attachments/", api.AttachmentsAPI.as_view(), name="api-attachments"),
    ]
