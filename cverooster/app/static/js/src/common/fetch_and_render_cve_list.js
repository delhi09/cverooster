const CVE_DESCRIPTION_MAX_LENGTH = 150;
const SEVERITY_CRITICAL = "CRITICAL";
const SEVERITY_HIGH = "HIGH";
const SEVERITY_MEDIUM = "MEDIUM";
const SEVERITY_LOW = "LOW";
const PREV_PAGE_DISP_LIMIT = 3;
const NEXT_PAGE_DISP_LIMIT = 3;
const ALL = "ALL";
const API_URL_CVE_LIST = "/api/cve/list";
const API_URL_SAVE_USER_CVE_COMMENT = "/api/cve/save_user_cve_comment";
const API_URL_DELETE_USER_CVE_COMMENT = "/api/cve/delete_user_cve_comment";
const API_URL_SAVE_USER_CVE_LABEL = "/api/cve/save_user_cve_label";
const API_URL_DELETE_USER_CVE_LABEL = "/api/cve/delete_user_cve_label";

var scroll_to_result_top = function (e) {
    if (e && e.pageY > $("#result_section").offset().top) {
        $("html,body").animate({ scrollTop: $("#result_section").offset().top });
    }
};

var render_cve_list = function (data) {
    var total_count = data.result.total_count;
    var display_count_from = data.result.display_count_from;
    var display_count_to = data.result.display_count_to;
    var current_page = data.result.current_page;
    var max_page = data.result.max_page;
    var cve_list = data.result.cve_list;
    var display_cve_list = [];
    moment.locale("ja")
    for (var i in cve_list) {
        var row = cve_list[i];
        var display_cve = {
            cve_id: null,
            detail_page_url: null,
            cve_url: null,
            nvd_content_exists: null,
            nvd_url: null,
            cve_description: null,
            published_date: null,
            severity: null,
            label_id: null,
            comment: null
        };
        display_cve.cve_id = row.cve_id;
        display_cve.detail_page_url = "/detail/" + row.cve_id;
        display_cve.cve_url = row.cve_url;
        display_cve.nvd_content_exists = row.nvd_content_exists;
        display_cve.nvd_url = row.nvd_content_exists ? row.nvd_url : null;
        if (row.cve_description.length > CVE_DESCRIPTION_MAX_LENGTH) {
            display_cve.cve_description = row.cve_description.substring(0, CVE_DESCRIPTION_MAX_LENGTH + 1) + "...";
        } else {
            display_cve.cve_description = row.cve_description;
        }
        if (row.published_date != null) {
            display_cve.published_date = moment(row.published_date).format("YYYY/M/D");
        } else {
            display_cve.published_date = "-";
        }
        if (row.cvss3_severity == SEVERITY_CRITICAL || row.cvss2_severity == SEVERITY_CRITICAL) {
            display_cve.severity = SEVERITY_CRITICAL;
        } else if (row.cvss3_severity == SEVERITY_HIGH || row.cvss2_severity == SEVERITY_HIGH) {
            display_cve.severity = SEVERITY_HIGH;
        } else if (row.cvss3_severity == SEVERITY_MEDIUM || row.cvss2_severity == SEVERITY_MEDIUM) {
            display_cve.severity = SEVERITY_MEDIUM;
        } else if (row.cvss3_severity == SEVERITY_LOW || row.cvss2_severity == SEVERITY_LOW) {
            display_cve.severity = SEVERITY_LOW;
        } else {
            display_cve.severity = "-";
        }
        display_cve.label_id = row.label_id;
        display_cve.comment = row.comment;
        display_cve_list.push(display_cve);
    }
    var template_args = {
        total_count: total_count,
        display_count_from: display_count_from,
        display_count_to: display_count_to,
        cve_list: display_cve_list,
        current_page: current_page,
        max_page: max_page,
        prev_page_disp_limit: PREV_PAGE_DISP_LIMIT,
        next_page_disp_limit: NEXT_PAGE_DISP_LIMIT,
    };
    var template = _.template($("script#cve_list_template_login").text());
    var html = template(template_args);
    $("div#result_section").html(html);
};

var control_label_checkbox_row = function () {
    $("input[class*='label_checkbox_']").on("click", function () {
        var target_class_name = null;
        var classes = $(this).attr("class").split(" ");
        for (var i in classes) {
            if (classes[i].startsWith('label_checkbox_')) {
                target_class_name = classes[i];
                break;
            }
        }
        var target_id = $(this).attr("id");
        $("input[type='checkbox']." + target_class_name).each(function () {
            if ($(this).attr("id") == target_id) {
                return true;
            }
            $(this).prop("checked", false);
        });
    });
};

var save_comment = function () {
    var cve_id = $(this).data("cve_id");
    var index = $(this).data("index");
    var comment = $("textarea#user_cve_comment_" + index).val();
    var csrf_token = Cookies.get("csrftoken");
    if (comment != "") {
        $.ajax({
            url: API_URL_SAVE_USER_CVE_COMMENT,
            type: "POST",
            headers: {
                "X-CSRFToken": csrf_token
            },
            data: {
                cve_id: cve_id,
                comment: comment
            }
        }).done(function (data) {
            if ($("div#save_comment_result_" + index).length > 0) {
                $("div#save_comment_result_" + index).text("保存しました。");
                $("div#save_comment_result_" + index).attr("class", "text-info");
            } else {
                $("button[data-index='" + index + "'].save_comment").after("<div id='save_comment_result_" + index + "' class='text-info' style='margin-top: 4px;'>保存しました。</div>");
            }
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if ($("div#save_comment_result_" + index).length > 0) {
                $("div#save_comment_result_" + index).text("保存に失敗しました。");
                $("div#save_comment_result_" + index).attr("class", "text-danger");
            } else {
                $("button[data-index='" + index + "'].save_comment").after("<div id='save_comment_result_" + index + "' class='text-danger' style='margin-top: 4px;'>保存に失敗しました。</div>");
            }
        });
    } else {
        $.ajax({
            url: API_URL_DELETE_USER_CVE_COMMENT,
            type: "DELETE",
            headers: {
                "X-CSRFToken": csrf_token
            },
            data: {
                cve_id: cve_id
            }
        }).done(function (data) {
            if ($("div#save_comment_result_" + index).length > 0) {
                $("div#save_comment_result_" + index).text("保存しました。");
                $("div#save_comment_result_" + index).attr("class", "text-info");
            } else {
                $("button[data-index='" + index + "'].save_comment").after("<div id='save_comment_result_" + index + "' class='text-info' style='margin-top: 4px;'>保存しました。</div>");
            }
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if ($("div#save_comment_result_" + index).length > 0) {
                $("div#save_comment_result_" + index).text("保存に失敗しました。");
                $("div#save_comment_result_" + index).attr("class", "text-danger");
            } else {
                $("button[data-index='" + index + "'].save_comment").after("<div id='save_comment_result_" + index + "' class='text-danger' style='margin-top: 4px;'>保存に失敗しました。</div>");
            }
        });
    }
};

var save_label = function () {
    var cve_id = $(this).data("cve_id");
    var index = $(this).data("index");
    var label = null;
    $("input[type='checkbox'].label_checkbox_" + index).each(function () {
        if ($(this).prop('checked')) {
            label = $(this).val();
            return false;
        }
    });
    var csrf_token = Cookies.get("csrftoken");
    if (label) {
        $.ajax({
            url: API_URL_SAVE_USER_CVE_LABEL,
            type: "POST",
            headers: {
                "X-CSRFToken": csrf_token
            },
            data: {
                cve_id: cve_id,
                label: label
            }
        }).done(function (data) {
            if ($("div#save_label_result_" + index).length > 0) {
                $("div#save_label_result_" + index).text("保存しました。");
                $("div#save_label_result_" + index).attr("class", "text-info");
            } else {
                $("button[data-index='" + index + "'].save_label").after("<div id='save_label_result_" + index + "' class='text-info' style='margin-top: 4px;'>保存しました。</div>");
            }
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if ($("div#save_label_result_" + index).length > 0) {
                $("div#save_label_result_" + index).text("保存に失敗しました。");
                $("div#save_label_result_" + index).attr("class", "text-danger");
            } else {
                $("button[data-index='" + index + "'].save_label").after("<div id='save_label_result_" + index + "' class='text-danger' style='margin-top: 4px;'>保存に失敗しました。</div>");
            }
        });
    } else {
        $.ajax({
            url: API_URL_DELETE_USER_CVE_LABEL,
            type: "DELETE",
            headers: {
                "X-CSRFToken": csrf_token
            },
            data: {
                cve_id: cve_id,
            }
        }).done(function (data) {
            if ($("div#save_label_result_" + index).length > 0) {
                $("div#save_label_result_" + index).text("保存しました。");
                $("div#save_label_result_" + index).attr("class", "text-info");
            } else {
                $("button[data-index='" + index + "'].save_label").after("<div id='save_label_result_" + index + "' class='text-info' style='margin-top: 4px;'>保存しました。</div>");
            }
        }).fail(function (jqXHR, textStatus, errorThrown) {
            if ($("div#save_label_result_" + index).length > 0) {
                $("div#save_label_result_" + index).text("保存に失敗しました。");
                $("div#save_label_result_" + index).attr("class", "text-danger");
            } else {
                $("button[data-index='" + index + "'].save_label").after("<div id='save_label_result_" + index + "' class='text-danger' style='margin-top: 4px;'>保存に失敗しました。</div>");
            }
        });
    }
};

var fetch_and_render_cve_list = function (e = null) {
    if (e != null) {
        e.preventDefault();
    }
    scroll_to_result_top(e);
    var params = collect_filter_conditions();
    var page = 1;
    if ($(this).attr("id") == "do_filter_reset_conditions") {
        page = 1;
    } else if ($(this).data("page")) {
        page = $(this).data("page");
    } else if ($("li.page-item.active a").data("page")) {
        page = $("li.page-item.active a").data("page");
    }
    params.push("page=" + page);
    api_url = API_URL_CVE_LIST + "?" + params.join("&");
    $.ajax({
        url: api_url,
        type: "GET",
    }).done(function (data) {
        render_cve_list(data);
        control_label_checkbox_row();

        $('.do_filter').off('click.fetch_and_render_cve_list');
        $(".do_filter").on("click.fetch_and_render_cve_list", fetch_and_render_cve_list);
        $("button.save_comment").on("click", save_comment);
        $("button.save_label").on("click", save_label);
    }).fail(function (jqXHR, textStatus, errorThrown) {
        alert("コンテンツの取得に失敗しました。");
    });
};