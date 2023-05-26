
/**
 * Функция, выполняющая AJAX-запрос на регистрацию пользователя при нажатии на кнопку "Зарегистрироваться".
 *
 * @returns {void}
 */
$(function(){
	$('#btnSignUp').click(function(){
		
		$.ajax({
			url: '/signUp',
			data: $('form').serialize(),
			type: 'POST',
			success: function(response){
				console.log(response);
			},
			error: function(error){
				console.log(error);
			}
		});
	});
});
