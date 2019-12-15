$(".toggle").click(function () {
    var target = $(this).parents(".nav").find(".menu")
    if (target.hasClass("open")) {
        target.removeClass("open")
    } else {
        target.addClass("open")
    }
})
$(".menu-item").mouseleave(function () {
    $(this).find(".sub-menu").css("display","none")
})
$(".menu-item").mouseenter(function () {
    $(this).find(".sub-menu").css("display","block")
})