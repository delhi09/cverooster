var control_label_checkbox = function () {
    $("input[type='checkbox'].check_label").on("click", function () {
        if ($(this).val() == ALL) {
            $("input[type='checkbox'].check_label").each(function () {
                if ($(this).val() != ALL) {
                    $(this).prop("checked", false);
                }
            });
        } else {
            $("input[type='checkbox']#label_all").prop("checked", false);
        }
    });
};

$(document).ready(function () {
    control_label_checkbox();
    fetch_and_render_cve_list();
});