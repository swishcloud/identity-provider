var app = {
    blockUi: function () {
        $("#mask").removeClass("d-none")
    },

    unBlockUi: function () {
        $("#mask").addClass("d-none")
    },

    showError: function (target, error) {
        $(target).append($('<div class="alert alert-danger" role="alert"></div>').text(error))
    },
    closeError: function (target) {
        $(target).find("div:first").alert("close")
    },
    ajaxSubmit: function (form, option, rules) {
        $(form).validate({
            rules: rules,
            submitHandler: function (form) {
                var before = option.before
                if (typeof before == "function")
                    before()
                $(form).ajaxSubmit({
                    success: function (res) {
                        if (typeof res.error === "undefined") {
                            res = {
                                error: "response data format from server is invalid"
                            }
                        }
                        var success = option.success
                        if (typeof success == "function")
                            success(res)
                        else {
                            throw Error("Missing required 'success' callback function.")
                        }
                    },
                    error: function () {
                        alert("server error")
                    }
                })
            }
        })
    },
    uuidv4: function uuidv4() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

$(document).ajaxStart(app.blockUi).ajaxComplete(app.unBlockUi)