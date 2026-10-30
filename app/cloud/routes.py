"""
Cloud File Storage Routes: upload, list, download, modify, and delete operations.
"""
from flask import (
    render_template,
    redirect,
    url_for,
    flash,
    request,
    send_file,
    abort,
)
from app.cloud import cloud_bp
from app.auth.decorators import login_required, get_current_user
from app.services.file_service import (
    save_uploaded_file,
    list_files_for_user,
    get_file_for_download,
    modify_file_content,
    delete_file,
)


def format_filesize(num_bytes: int) -> str:
    """Helper to format file sizes in human-readable units (B, KB, MB, GB)."""
    if num_bytes is None:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


@cloud_bp.route("/")
@cloud_bp.route("/files")
@login_required
def files():
    """Display the cloud file management portal."""
    current_user = get_current_user()
    user_files = list_files_for_user(current_user)

    total_bytes = sum(f.filesize for f in user_files)
    formatted_total_size = format_filesize(total_bytes)

    # Attach human-readable formatted sizes to each file object for rendering
    for f in user_files:
        f.formatted_size = format_filesize(f.filesize)

    return render_template(
        "cloud/index.html",
        files=user_files,
        total_files=len(user_files),
        total_storage=formatted_total_size,
        current_user=current_user,
    )


@cloud_bp.route("/upload", methods=["POST"])
@login_required
def upload():
    """Handle new file upload."""
    current_user = get_current_user()

    if "file" not in request.files:
        flash("No file part detected in request.", "danger")
        return redirect(url_for("cloud.files"))

    uploaded_file = request.files["file"]
    if not uploaded_file or uploaded_file.filename == "":
        flash("Please select a file to upload.", "warning")
        return redirect(url_for("cloud.files"))

    try:
        file_record = save_uploaded_file(uploaded_file, current_user)
        flash(f"File '{file_record.filename}' uploaded and logged successfully.", "success")
    except ValueError as ve:
        flash(f"Upload failed: {str(ve)}", "danger")
    except PermissionError as pe:
        flash(f"Security error: {str(pe)}", "danger")
    except Exception as e:
        flash(f"An unexpected error occurred during upload: {str(e)}", "danger")

    return redirect(url_for("cloud.files"))


@cloud_bp.route("/download/<int:file_id>")
@login_required
def download(file_id: int):
    """Download permitted cloud storage file."""
    current_user = get_current_user()

    try:
        physical_path, original_filename = get_file_for_download(file_id, current_user)
        return send_file(
            physical_path,
            as_attachment=True,
            download_name=original_filename,
        )
    except FileNotFoundError:
        abort(404, description="The requested file was not found.")
    except PermissionError:
        abort(403, description="Access denied: You do not have permission to download this file.")
    except Exception as e:
        flash(f"Download failed: {str(e)}", "danger")
        return redirect(url_for("cloud.files"))


@cloud_bp.route("/modify/<int:file_id>", methods=["POST"])
@login_required
def modify(file_id: int):
    """Modify/replace an existing cloud storage file's content."""
    current_user = get_current_user()

    if "file" not in request.files:
        flash("No replacement file part provided.", "danger")
        return redirect(url_for("cloud.files"))

    replacement_file = request.files["file"]
    if not replacement_file or replacement_file.filename == "":
        flash("Please select a replacement file.", "warning")
        return redirect(url_for("cloud.files"))

    try:
        file_record = modify_file_content(file_id, replacement_file, current_user)
        flash(f"File '{file_record.filename}' content modified and logged successfully.", "success")
    except FileNotFoundError:
        abort(404, description="Target file not found for modification.")
    except PermissionError:
        abort(403, description="Access denied: You do not have permission to modify this file.")
    except ValueError as ve:
        flash(f"Modification failed: {str(ve)}", "danger")
    except Exception as e:
        flash(f"Unexpected error during modification: {str(e)}", "danger")

    return redirect(url_for("cloud.files"))


@cloud_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id: int):
    """Delete cloud file and preserve the deletion audit event."""
    current_user = get_current_user()

    try:
        delete_file(file_id, current_user)
        flash("File deleted successfully. Deletion event has been recorded in the audit log.", "info")
    except FileNotFoundError:
        abort(404, description="Target file not found for deletion.")
    except PermissionError:
        abort(403, description="Access denied: You do not have permission to delete this file.")
    except Exception as e:
        flash(f"Deletion failed: {str(e)}", "danger")

    return redirect(url_for("cloud.files"))
