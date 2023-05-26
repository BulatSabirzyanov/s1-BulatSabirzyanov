/**
 * Функция, выполняющая AJAX-запрос на валидацию данных при нажатии на кнопку "Войти" (для формы входа).
 *
 * @returns {void}
 */
$(function(){
	$('#btnSignIn1').click(function(){
		
		$.ajax({
			url: '/validateLogin',
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

/**
 * Функция, выполняющая AJAX-запрос на валидацию данных при нажатии на кнопку "Войти" (для формы входа).
 * Предполагается, что кнопка имеет идентификатор 'btnSignIn'.
 *
 * @returns {void}
 */
$(function(){
  $('#btnGitHubLogin').click(function(){
    window.location.href = '/login/github';  // Redirect to the GitHub login page
  });

  $('#btnSignIn').click(function(){
    $.ajax({
      url: '/validateLogin',
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


/**
 * Функция, выполняющая AJAX-запрос на сброс пароля пользователя при нажатии на кнопку "Сбросить пароль".
 *
 * @returns {void}
 */
$(function(){
  $('#resetPassword').click(function(){
      window.location.href ='/reset_password'
   $.ajax({
			url: '/reset_password',
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