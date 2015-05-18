require 'test_helper'

class CapturesControllerTest < ActionController::TestCase
  def test_should_get_index
    get :index
    assert_response :success
    assert_not_nil assigns(:captures)
  end

  def test_should_get_new
    get :new
    assert_response :success
  end

  def test_should_create_capture
    assert_difference('Capture.count') do
      post :create, :capture => { }
    end

    assert_redirected_to capture_path(assigns(:capture))
  end

  def test_should_show_capture
    get :show, :id => captures(:one).id
    assert_response :success
  end

  def test_should_get_edit
    get :edit, :id => captures(:one).id
    assert_response :success
  end

  def test_should_update_capture
    put :update, :id => captures(:one).id, :capture => { }
    assert_redirected_to capture_path(assigns(:capture))
  end

  def test_should_destroy_capture
    assert_difference('Capture.count', -1) do
      delete :destroy, :id => captures(:one).id
    end

    assert_redirected_to captures_path
  end
end
