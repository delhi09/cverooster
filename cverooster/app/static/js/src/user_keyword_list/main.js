const API_URL_SAVE_USER_KEYWORD = "/api/cve/save_user_keyword";
const API_URL_DELETE_USER_KEYWORD = "/api/cve/delete_user_keyword";

var delete_keyword = function () {
    var keyword = $(this).data("keyword");
    var csrf_token = Cookies.get("csrftoken");
    $.ajax({
        url: API_URL_DELETE_USER_KEYWORD,
        type: "DELETE",
        headers: {
            "X-CSRFToken": csrf_token
        },
        data: {
            keyword: keyword
        }
    }).done(function (data) {
        $("div#registered_keyword_list button[data-keyword='" + keyword + "']").remove();
    });
};

var save_keyword = function () {
    var keyword = $("input[type='text']#input_keyword").val();
    var csrf_token = Cookies.get("csrftoken");
    $.ajax({
        url: API_URL_SAVE_USER_KEYWORD,
        type: "POST",
        headers: {
            "X-CSRFToken": csrf_token
        },
        data: {
            keyword: keyword
        }
    }).done(function (data) {
        var template = _.template($("script#keyword_button_template").text());
        var html = template({ keyword: keyword });
        $("div#registered_keyword_list").append(html);
        $("button.registered_keyword").off("click.delete_keyword");
        $("button.registered_keyword").on("click.delete_keyword", delete_keyword);
    });
};

$(document).ready(function () {
    fetch_and_render_cve_list();
    $("button#save_keyword").on("click.save_keyword", save_keyword);
    $("button.registered_keyword").on("click.delete_keyword", delete_keyword);
});