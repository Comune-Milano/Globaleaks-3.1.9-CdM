GLClient.controller('LoginCtrl', ['$scope', '$location', 'Authentication', function($scope, $location, authentication) {
  // If already logged in, just go to the landing page.
  if ($scope.session !== undefined && $scope.session.auth_landing_page) {
    $location.path($scope.session.auth_landing_page);
  }

  $scope.auth_code_1 = '';
  $scope.auth_code_2 = '';
  $scope.auth_code_3 = '';

  $scope.simplifiedLogin = !!($location.path() === '/login' && $scope.node.simplified_login);

  $scope.token = $location.search().token;

  if ($scope.token) {
    $scope.Authentication.login('', '', '', '', '', $scope.token);
  }
}]);
